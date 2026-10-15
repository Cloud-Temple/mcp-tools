"""Schéma d'accès #31 ; installation opérateur explicite, aucun runtime DDL."""

import hashlib

VERSION = 1
DDL = r'''
CREATE SCHEMA tools_access;
REVOKE ALL ON SCHEMA tools_access FROM PUBLIC;
CREATE FUNCTION tools_access.valid_tools(values_ text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT values_ IS NOT NULL AND cardinality(values_) BETWEEN 0 AND 128
 AND (cardinality(values_)=0 OR (array_ndims(values_)=1 AND array_lower(values_,1)=1))
 AND NOT EXISTS(SELECT 1 FROM unnest(values_) value WHERE value IS NULL OR value !~ '^[a-z][a-z0-9_]{0,63}$')
 AND cardinality(values_)=(SELECT count(DISTINCT value) FROM unnest(values_) value)
$$;
CREATE TABLE tools_access.schema_version (
 singleton boolean PRIMARY KEY CHECK(singleton), version integer NOT NULL CHECK(version=1), checksum text NOT NULL
);
CREATE TABLE tools_access.hub_actor_bindings (
 id uuid PRIMARY KEY, issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 subject text NOT NULL CHECK(subject ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 actor_id uuid NOT NULL, tenant_id text NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 service_id text NOT NULL CHECK(service_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 enabled boolean NOT NULL, version bigint NOT NULL CHECK(version>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(issuer,subject,tenant_id,service_id)
);
CREATE TABLE tools_access.access_credentials (
 token_hash text PRIMARY KEY CHECK(token_hash ~ '^[0-9a-f]{64}$'), actor_id uuid NOT NULL,
 tenant_id text NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 service_id text NOT NULL CHECK(service_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 client_name text NOT NULL CHECK(client_name ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 permissions text[] NOT NULL CHECK(permissions <@ ARRAY['access','admin']::text[] AND array_position(permissions,NULL) IS NULL
    AND cardinality(permissions)<=2 AND (cardinality(permissions)=0 OR (array_ndims(permissions)=1 AND array_lower(permissions,1)=1))
    AND (cardinality(permissions)<2 OR permissions[1]<>permissions[2])),
 tool_ids text[] NOT NULL CHECK(tools_access.valid_tools(tool_ids)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz, revoked_at timestamptz,
 version bigint NOT NULL CHECK(version>0), CHECK(expires_at IS NULL OR expires_at>created_at),
 CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE TABLE tools_access.activity_calls (
 id uuid PRIMARY KEY, actor_id uuid, tenant_id text, service_id text,
 tool text NOT NULL CHECK(tool ~ '^[a-z][a-z0-9_]{0,63}$'),
 trace_id uuid NOT NULL, operation_id uuid, mission_id text,
 category text NOT NULL CHECK(category IN ('technical','mission')),
 admission text NOT NULL CHECK(admission IN ('admitted','denied')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 CHECK(expires_at=created_at+CASE category WHEN 'technical' THEN interval '720 hours' ELSE interval '8760 hours' END),
 CHECK((category='technical' AND mission_id IS NULL) OR (category='mission' AND mission_id IS NOT NULL AND mission_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')),
 CHECK((actor_id IS NULL AND tenant_id IS NULL AND service_id IS NULL AND admission='denied')
    OR (actor_id IS NOT NULL AND tenant_id IS NOT NULL AND service_id IS NOT NULL AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
        AND service_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'))
);
CREATE TABLE tools_access.activity_events (
 id uuid PRIMARY KEY, call_id uuid NOT NULL REFERENCES tools_access.activity_calls(id),
 phase text NOT NULL CHECK(phase IN ('terminal','access_mutation')),
 outcome text NOT NULL CHECK(outcome IN ('completed','denied','failed','uncertain')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(call_id,phase)
);
CREATE INDEX activity_expiry ON tools_access.activity_calls(expires_at,id);
CREATE INDEX activity_actor ON tools_access.activity_calls(tenant_id,actor_id,created_at,id);
CREATE FUNCTION tools_access.guard_credential() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(OLD.token_hash,OLD.actor_id,OLD.tenant_id,OLD.service_id,OLD.created_at,OLD.expires_at)
 IS DISTINCT FROM ROW(NEW.token_hash,NEW.actor_id,NEW.tenant_id,NEW.service_id,NEW.created_at,NEW.expires_at)
 OR NEW.version<>OLD.version+1 OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
 THEN RAISE EXCEPTION 'immutable access identity or expiry'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER credential_identity BEFORE UPDATE ON tools_access.access_credentials
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_credential();
CREATE FUNCTION tools_access.guard_history() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'append only activity'; END $$;
CREATE TRIGGER immutable_calls BEFORE UPDATE ON tools_access.activity_calls FOR EACH ROW EXECUTE FUNCTION tools_access.guard_history();
CREATE TRIGGER immutable_events BEFORE UPDATE ON tools_access.activity_events FOR EACH ROW EXECUTE FUNCTION tools_access.guard_history();
CREATE FUNCTION tools_access.credential_get(requested_hash text) RETURNS SETOF tools_access.access_credentials
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF requested_hash IS NULL OR requested_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid credential binding'; END IF;
 RETURN QUERY SELECT c.* FROM tools_access.access_credentials c WHERE c.token_hash=requested_hash
 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp());
END $$;
CREATE FUNCTION tools_access.admit_technical(requested_id uuid, requested_hash text, requested_tool text,
 requested_trace uuid, requested_operation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE; authorized boolean; selected boolean; stamp timestamptz:=clock_timestamp();
BEGIN
 IF requested_hash IS NULL OR requested_hash !~ '^[0-9a-f]{64}$'
 OR requested_tool IS NULL OR requested_tool !~ '^[a-z][a-z0-9_]{0,63}$' THEN RAISE EXCEPTION 'invalid admission'; END IF;
 SELECT c.* INTO actor FROM tools_access.access_credentials c WHERE c.token_hash=requested_hash
 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>stamp) FOR SHARE;
 selected:=FOUND;
 authorized:=selected AND ('admin'=ANY(actor.permissions) OR ('access'=ANY(actor.permissions) AND requested_tool=ANY(actor.tool_ids)));
 INSERT INTO tools_access.activity_calls(id,actor_id,tenant_id,service_id,tool,trace_id,operation_id,category,admission,created_at,expires_at)
 VALUES(requested_id,CASE WHEN selected THEN actor.actor_id END,CASE WHEN selected THEN actor.tenant_id END,
 CASE WHEN selected THEN actor.service_id END,requested_tool,requested_trace,requested_operation,'technical',
 CASE WHEN authorized THEN 'admitted' ELSE 'denied' END,stamp,stamp+interval '720 hours');
 RETURN authorized;
END $$;
CREATE FUNCTION tools_access.finish_activity(requested_call uuid, requested_outcome text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing text; inserted integer; admission_state text;
BEGIN
 IF requested_outcome IS NULL OR requested_outcome NOT IN ('completed','denied','failed','uncertain') THEN RAISE EXCEPTION 'invalid outcome'; END IF;
 SELECT c.admission INTO admission_state FROM tools_access.activity_calls c WHERE c.id=requested_call FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown activity'; END IF;
 IF admission_state='denied' AND requested_outcome<>'denied' THEN RAISE EXCEPTION 'denied admission has no effect'; END IF;
 INSERT INTO tools_access.activity_events(id,call_id,phase,outcome) VALUES(gen_random_uuid(),requested_call,'terminal',requested_outcome)
 ON CONFLICT(call_id,phase) DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;
 SELECT e.outcome INTO existing FROM tools_access.activity_events e WHERE e.call_id=requested_call AND e.phase='terminal';
 IF existing IS DISTINCT FROM requested_outcome THEN RAISE EXCEPTION 'conflicting terminal'; END IF;
 RETURN inserted=1;
END $$;
CREATE FUNCTION tools_access.purge_expired(requested_limit integer) RETURNS TABLE(calls bigint,events bigint,credentials bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ids uuid[]; hashes text[]; stamp timestamptz:=clock_timestamp();
BEGIN
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'invalid purge bound'; END IF;
 SELECT array_agg(target.id) INTO ids FROM (SELECT c.id FROM tools_access.activity_calls c
 WHERE c.expires_at<=stamp ORDER BY c.expires_at,c.id LIMIT requested_limit FOR UPDATE SKIP LOCKED) target;
 DELETE FROM tools_access.activity_events e WHERE e.call_id=ANY(ids); GET DIAGNOSTICS events=ROW_COUNT;
 DELETE FROM tools_access.activity_calls c WHERE c.id=ANY(ids); GET DIAGNOSTICS calls=ROW_COUNT;
 SELECT array_agg(target.token_hash) INTO hashes FROM (SELECT c.token_hash FROM tools_access.access_credentials c
 WHERE c.expires_at<=stamp ORDER BY c.expires_at,c.token_hash LIMIT requested_limit FOR UPDATE SKIP LOCKED) target;
 DELETE FROM tools_access.access_credentials c WHERE c.token_hash=ANY(hashes); GET DIAGNOSTICS credentials=ROW_COUNT;
 RETURN NEXT;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA tools_access FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tools_access FROM PUBLIC;
'''
CHECKSUM = hashlib.sha256(DDL.encode()).hexdigest()

APP_ROUTINES = ("credential_get(text)", "admit_technical(uuid,text,text,uuid,uuid)", "finish_activity(uuid,text)")
MAINTENANCE_ROUTINES = ("purge_expired(integer)",)
