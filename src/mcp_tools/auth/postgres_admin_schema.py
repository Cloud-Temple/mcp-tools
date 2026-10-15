"""Routines admin #31 : autorité fraîche, mutation et trace dans la même TX."""

ADMIN_DDL = r'''
CREATE FUNCTION tools_access.require_admin(requested_hash text) RETURNS tools_access.access_credentials
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE;
BEGIN
 SELECT c.* INTO actor FROM tools_access.access_credentials c
 WHERE c.token_hash=requested_hash FOR SHARE;
 IF NOT FOUND OR actor.revoked_at IS NOT NULL OR NOT ('admin'=ANY(actor.permissions))
 OR (actor.expires_at IS NOT NULL AND actor.expires_at<=clock_timestamp())
 THEN RAISE EXCEPTION 'current admin required' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $$;
CREATE FUNCTION tools_access.record_admin(actor tools_access.access_credentials, requested_id uuid,
 requested_tool text, target_actor uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE stamp timestamptz:=clock_timestamp();
BEGIN
 INSERT INTO tools_access.activity_calls(id,actor_id,tenant_id,service_id,tool,trace_id,operation_id,
 category,admission,created_at,expires_at)
 VALUES(requested_id,actor.actor_id,actor.tenant_id,actor.service_id,requested_tool,requested_id,requested_id,
 'technical','admitted',stamp,stamp+interval '720 hours');
 INSERT INTO tools_access.activity_events(id,call_id,phase,outcome,target_actor_id)
 VALUES(gen_random_uuid(),requested_id,'access_mutation','completed',target_actor);
END $$;
CREATE FUNCTION tools_access.credential_create(requester text, requested_operation uuid, requested_hash text,
 requested_actor uuid, requested_tenant text, requested_service text, requested_client text,
 requested_permissions text[], requested_tools text[], requested_expiry timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE admin_actor tools_access.access_credentials%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(requested_actor::text,31));
 admin_actor:=tools_access.require_admin(requester);
 IF EXISTS(SELECT 1 FROM tools_access.access_credentials c WHERE c.actor_id=requested_actor
 AND ROW(c.tenant_id,c.service_id) IS DISTINCT FROM ROW(requested_tenant,requested_service))
 OR EXISTS(SELECT 1 FROM tools_access.activity_calls c WHERE c.actor_id=requested_actor
 AND ROW(c.tenant_id,c.service_id) IS DISTINCT FROM ROW(requested_tenant,requested_service))
 OR EXISTS(SELECT 1 FROM tools_access.hub_actor_bindings b WHERE b.actor_id=requested_actor
 AND ROW(b.tenant_id,b.service_id) IS DISTINCT FROM ROW(requested_tenant,requested_service))
 THEN RAISE EXCEPTION 'actor identity cannot move'; END IF;
 INSERT INTO tools_access.access_credentials(token_hash,actor_id,tenant_id,service_id,client_name,
 permissions,tool_ids,expires_at,version)
 VALUES(requested_hash,requested_actor,requested_tenant,requested_service,requested_client,
 requested_permissions,requested_tools,requested_expiry,1);
 PERFORM tools_access.record_admin(admin_actor,requested_operation,'access_create',requested_actor);
 RETURN true;
END $$;
CREATE FUNCTION tools_access.credential_update(requester text, requested_operation uuid, requested_hash text,
 expected_version bigint, requested_client text, requested_permissions text[], requested_tools text[]) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE admin_actor tools_access.access_credentials%ROWTYPE; changed_actor uuid;
BEGIN
 admin_actor:=tools_access.require_admin(requester);
 UPDATE tools_access.access_credentials SET client_name=requested_client,permissions=requested_permissions,
 tool_ids=requested_tools,version=version+1 WHERE token_hash=requested_hash AND version=expected_version
 AND revoked_at IS NULL RETURNING actor_id INTO changed_actor;
 IF NOT FOUND THEN RAISE EXCEPTION 'access version conflict'; END IF;
 -- FOR SHARE conserve les droits/revocations externes jusqu'à la fin de TX ;
 -- l'horloge serveur peut toutefois dépasser l'expiration pendant UPDATE.
 IF admin_actor.expires_at IS NOT NULL AND admin_actor.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'current admin required' USING ERRCODE='42501'; END IF;
 PERFORM tools_access.record_admin(admin_actor,requested_operation,'access_update',changed_actor);
 RETURN true;
END $$;
CREATE FUNCTION tools_access.credential_revoke(requester text, requested_operation uuid,
 requested_hash text, expected_version bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE admin_actor tools_access.access_credentials%ROWTYPE; changed_actor uuid;
BEGIN
 admin_actor:=tools_access.require_admin(requester);
 UPDATE tools_access.access_credentials SET revoked_at=clock_timestamp(),version=version+1
 WHERE token_hash=requested_hash AND version=expected_version AND revoked_at IS NULL
 RETURNING actor_id INTO changed_actor;
 IF NOT FOUND THEN RAISE EXCEPTION 'access version conflict'; END IF;
 IF admin_actor.expires_at IS NOT NULL AND admin_actor.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'current admin required' USING ERRCODE='42501'; END IF;
 PERFORM tools_access.record_admin(admin_actor,requested_operation,'access_revoke',changed_actor);
 RETURN true;
END $$;
CREATE FUNCTION tools_access.credential_list(requester text, after_hash text, requested_limit integer)
RETURNS TABLE(cursor_key text, token_prefix text, actor_id uuid, tenant_id text, service_id text, client_name text,
 permissions text[], tool_ids text[], created_at timestamptz, expires_at timestamptz, revoked boolean, version bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM tools_access.require_admin(requester);
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 100
 OR (after_hash IS NOT NULL AND after_hash !~ '^[0-9a-f]{64}$') THEN RAISE EXCEPTION 'invalid page'; END IF;
 RETURN QUERY SELECT c.token_hash,left(c.token_hash,12),c.actor_id,c.tenant_id,c.service_id,c.client_name,c.permissions,
 c.tool_ids,c.created_at,c.expires_at,c.revoked_at IS NOT NULL,c.version
 FROM tools_access.access_credentials c WHERE after_hash IS NULL OR c.token_hash>after_hash
 ORDER BY c.token_hash LIMIT requested_limit;
END $$;
CREATE FUNCTION tools_access.activity_page(requester text, before_stamp timestamptz,
 before_id uuid, requested_limit integer)
RETURNS TABLE(call_id uuid, actor_id uuid, tenant_id text, service_id text, tool text,
 trace_id uuid, operation_id uuid, mission_id text, category text, admission text,
 created_at timestamptz, expires_at timestamptz, outcome text, target_actor_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE;
BEGIN
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 100
 OR (before_stamp IS NULL)<>(before_id IS NULL) THEN RAISE EXCEPTION 'invalid page'; END IF;
 SELECT c.* INTO actor FROM tools_access.access_credentials c WHERE c.token_hash=requester FOR SHARE;
 IF NOT FOUND OR actor.revoked_at IS NOT NULL OR
 NOT ('admin'=ANY(actor.permissions) OR 'access'=ANY(actor.permissions)) OR
 (actor.expires_at IS NOT NULL AND actor.expires_at<=clock_timestamp())
 THEN RAISE EXCEPTION 'current access required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT c.id,c.actor_id,c.tenant_id,c.service_id,c.tool,c.trace_id,c.operation_id,
 c.mission_id,c.category,c.admission,c.created_at,c.expires_at,e.outcome,e.target_actor_id
 FROM tools_access.activity_calls c LEFT JOIN LATERAL
 (SELECT event.outcome,event.target_actor_id FROM tools_access.activity_events event WHERE event.call_id=c.id
 ORDER BY (event.phase='terminal') DESC LIMIT 1) e ON true
 WHERE (c.expires_at>clock_timestamp())
 AND ('admin'=ANY(actor.permissions) OR (c.actor_id=actor.actor_id AND c.tenant_id=actor.tenant_id
 AND c.service_id=actor.service_id AND c.tool=ANY(actor.tool_ids)))
 AND (before_stamp IS NULL OR ROW(c.created_at,c.id)<ROW(before_stamp,before_id))
 ORDER BY c.created_at DESC,c.id DESC LIMIT requested_limit;
END $$;
'''

ADMIN_ROUTINES = (
    'credential_create(text,uuid,text,uuid,text,text,text,text[],text[],timestamptz)',
    'credential_update(text,uuid,text,bigint,text,text[],text[])',
    'credential_revoke(text,uuid,text,bigint)', 'credential_list(text,text,integer)',
    'activity_page(text,timestamptz,uuid,integer)',
)
