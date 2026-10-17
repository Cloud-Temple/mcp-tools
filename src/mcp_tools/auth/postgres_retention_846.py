"""#846 : extension holds846 du domaine Access, rendue seulement sur un domaine neuf.

Le DDL v1 et son CHECKSUM restent identiques. L'extension ajoute un marqueur,
un registre de retrait par (tenant, mission), les identifiants retirés et cinq
routines de remplacement aux noms distincts. Les routines v1 remplacées restent
dans le schéma mais ne sont accordées à personne. Un call ``mission`` n'a plus
d'échéance par date : seul un retrait appuyé sur une claim Mission vérifiée le
supprime, quand ``clock_timestamp() > max(expires_at, retain_until)``.

Verrou de scope : ``hashtextextended('tools-retention-846:'||[tenant,mission],846)``.
Exclusif dans prepare, batch et status ; partagé dans le trigger d'admission.
"""
import hashlib

from .postgres_admin_schema import ADMIN_ROUTINES
from .postgres_admin_lookup import LOOKUP_ROUTINES
from .postgres_hub_schema import HUB_ROUTINES

VERSION = 1
_LOCK = "hashtextextended('tools-retention-846:'||jsonb_build_array({t},{m})::text,846)"
_DIGEST = ("(SELECT encode(sha256(convert_to(coalesce(string_agg(f.ref_id::text,E'\\n' ORDER BY f.ref_id::text "
           "COLLATE \"C\"),''),'UTF8')),'hex') FROM tools_access.mission_retired_refs_846 f "
           "WHERE f.operation_id=requested_operation AND f.kind='{kind}')")

DDL = r'''
CREATE TABLE tools_access.retention_846_version (
 singleton boolean PRIMARY KEY CHECK(singleton), version integer NOT NULL CHECK(version=1),
 checksum text NOT NULL, coordination_required boolean NOT NULL CHECK(coordination_required)
);
CREATE TABLE tools_access.mission_retirements_846 (
 operation_id uuid PRIMARY KEY,
 tenant_id text NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 mission_id text NOT NULL CHECK(mission_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 root_agent_id text NOT NULL CHECK(root_agent_id='' OR root_agent_id ~ '^ag_[A-Za-z0-9_-]+$'),
 claim_id uuid NOT NULL, claim_revision bigint NOT NULL CHECK(claim_revision>0),
 claim_sha256 text NOT NULL CHECK(claim_sha256 ~ '^[0-9a-f]{64}$'), retain_until timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','sealed')),
 prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(), sealed_at timestamptz,
 calls bigint, events bigint, calls_sha256 text, events_sha256 text,
 UNIQUE(tenant_id,mission_id), CHECK((state='sealed')=(sealed_at IS NOT NULL))
);
CREATE TABLE tools_access.mission_retired_refs_846 (
 operation_id uuid NOT NULL REFERENCES tools_access.mission_retirements_846(operation_id),
 kind text NOT NULL CHECK(kind IN ('call','event')), ref_id uuid NOT NULL,
 PRIMARY KEY(operation_id,kind,ref_id)
);
CREATE FUNCTION tools_access.guard_retirement_846() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.state<>'prepared' OR NEW.state<>'sealed'
 OR ROW(NEW.operation_id,NEW.tenant_id,NEW.mission_id,NEW.root_agent_id,NEW.claim_id,NEW.claim_revision,
  NEW.claim_sha256,NEW.retain_until,NEW.prepared_at)
 IS DISTINCT FROM ROW(OLD.operation_id,OLD.tenant_id,OLD.mission_id,OLD.root_agent_id,OLD.claim_id,OLD.claim_revision,
  OLD.claim_sha256,OLD.retain_until,OLD.prepared_at)
 THEN RAISE EXCEPTION 'immutable mission retirement'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retirement_846_identity BEFORE UPDATE OR DELETE ON tools_access.mission_retirements_846
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_retirement_846();
CREATE TRIGGER retired_refs_846_append BEFORE UPDATE OR DELETE ON tools_access.mission_retired_refs_846
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_history();
CREATE TRIGGER retention_846_immutable BEFORE UPDATE OR DELETE ON tools_access.retention_846_version
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_history();
CREATE FUNCTION tools_access.guard_mission_admission_846() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.category='mission' THEN
  -- Partagé : deux admissions coexistent ; prepare, exclusif, attend leur COMMIT.
  PERFORM pg_advisory_xact_lock_shared(@LOCK_NEW@);
  IF EXISTS(SELECT 1 FROM tools_access.mission_retirements_846 r
   WHERE r.tenant_id=NEW.tenant_id AND r.mission_id=NEW.mission_id)
  THEN RAISE EXCEPTION 'mission retention closed' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION tools_access.guard_mission_delete_846() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.category='mission' AND NOT EXISTS(SELECT 1 FROM tools_access.mission_retirements_846 r
  WHERE r.tenant_id=OLD.tenant_id AND r.mission_id=OLD.mission_id AND r.root_agent_id=OLD.root_agent_id
  AND r.state='prepared')
 THEN RAISE EXCEPTION 'mission activity retained until a verified retirement'; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER retention_846_admission BEFORE INSERT ON tools_access.activity_calls
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_mission_admission_846();
CREATE TRIGGER retention_846_delete BEFORE DELETE ON tools_access.activity_calls
 FOR EACH ROW EXECUTE FUNCTION tools_access.guard_mission_delete_846();
CREATE FUNCTION tools_access.retention_846_contract() RETURNS TABLE(version integer, checksum text, coordination_required boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT v.version,v.checksum,v.coordination_required FROM tools_access.retention_846_version v WHERE v.singleton
$$;
CREATE FUNCTION tools_access.activity_page_846(requester text, before_stamp timestamptz,
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
 -- Un call mission retenu n'a pas d'échéance publiée : NULL, jamais une date passée.
 RETURN QUERY SELECT c.id,c.actor_id,c.tenant_id,c.service_id,c.tool,c.trace_id,c.operation_id,
 c.mission_id,c.category,c.admission,c.created_at,
 CASE WHEN c.category='mission' THEN NULL::timestamptz ELSE c.expires_at END,e.outcome,e.target_actor_id
 FROM tools_access.activity_calls c LEFT JOIN LATERAL
 (SELECT event.outcome,event.target_actor_id FROM tools_access.activity_events event WHERE event.call_id=c.id
 ORDER BY (event.phase='terminal') DESC LIMIT 1) e ON true
 WHERE (c.category='mission' OR c.expires_at>clock_timestamp())
 AND ('admin'=ANY(actor.permissions) OR (c.actor_id=actor.actor_id AND c.tenant_id=actor.tenant_id
 AND c.service_id=actor.service_id AND c.tool=ANY(actor.tool_ids)))
 AND (before_stamp IS NULL OR ROW(c.created_at,c.id)<ROW(before_stamp,before_id))
 ORDER BY c.created_at DESC,c.id DESC LIMIT requested_limit;
END $$;
CREATE FUNCTION tools_access.hub_activity_page_846(requester text, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text, requested_mission text,
 requested_root text, before_stamp timestamptz, before_id uuid, requested_limit integer)
RETURNS TABLE(call_id uuid, actor_id uuid, tenant_id text, service_id text, tool text,
 trace_id uuid, operation_id uuid, mission_id text, category text, admission text,
 created_at timestamptz, expires_at timestamptz, outcome text, target_actor_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding tools_access.hub_actor_bindings%ROWTYPE; actor tools_access.access_credentials%ROWTYPE;
BEGIN
 SELECT b.* INTO STRICT binding FROM tools_access.hub_binding_get(requester,requested_issuer,
 requested_subject,requested_owner,requested_tenant) b;
 SELECT a.* INTO STRICT actor FROM tools_access.access_credentials a WHERE a.token_hash=requester FOR SHARE;
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 100
 OR (before_stamp IS NULL)<>(before_id IS NULL) THEN RAISE EXCEPTION 'invalid page'; END IF;
 RETURN QUERY SELECT c.id,c.actor_id,c.tenant_id,c.service_id,c.tool,c.trace_id,c.operation_id,
 c.mission_id,c.category,c.admission,c.created_at,NULL::timestamptz,e.outcome,e.target_actor_id
 FROM tools_access.activity_calls c LEFT JOIN LATERAL
 (SELECT event.outcome,event.target_actor_id FROM tools_access.activity_events event WHERE event.call_id=c.id
 ORDER BY (event.phase='terminal') DESC LIMIT 1) e ON true
 WHERE c.actor_id=binding.actor_id AND c.tenant_id=binding.tenant_id AND c.service_id=binding.service_id
 AND ('admin'=ANY(actor.permissions) OR c.tool=ANY(actor.tool_ids))
 AND c.mission_id=requested_mission AND c.root_agent_id=requested_root
 AND NOT EXISTS(SELECT 1 FROM tools_access.mission_retirements_846 r
  WHERE r.tenant_id=c.tenant_id AND r.mission_id=c.mission_id)
 AND (before_stamp IS NULL OR ROW(c.created_at,c.id)<ROW(before_stamp,before_id))
 ORDER BY c.created_at DESC,c.id DESC LIMIT requested_limit;
END $$;
CREATE FUNCTION tools_access.hub_file_calls_846(requester text, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text, requested_mission text,
 requested_root text, requested_calls uuid[])
RETURNS TABLE(call_id uuid, operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding tools_access.hub_actor_bindings%ROWTYPE; actor tools_access.access_credentials%ROWTYPE;
BEGIN
 SELECT b.* INTO STRICT binding FROM tools_access.hub_binding_get(requester,requested_issuer,
 requested_subject,requested_owner,requested_tenant) b;
 SELECT a.* INTO STRICT actor FROM tools_access.access_credentials a WHERE a.token_hash=requester FOR SHARE;
 IF actor.permissions<>ARRAY['hub_read']::text[] OR NOT ('files'=ANY(actor.tool_ids)) THEN RETURN; END IF;
 IF requested_calls IS NULL OR cardinality(requested_calls) NOT BETWEEN 1 AND 64
 OR array_ndims(requested_calls)<>1 OR array_position(requested_calls,NULL) IS NOT NULL
 THEN RAISE EXCEPTION 'hub file read refused' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT c.id,c.operation_id FROM tools_access.activity_calls c
 WHERE c.id=ANY(requested_calls) AND c.actor_id=binding.actor_id
 AND c.tenant_id=binding.tenant_id AND c.service_id=binding.service_id
 AND c.mission_id=requested_mission AND c.root_agent_id=requested_root
 AND c.tool='files' AND c.admission='admitted' AND c.category='mission'
 AND NOT EXISTS(SELECT 1 FROM tools_access.mission_retirements_846 r
  WHERE r.tenant_id=c.tenant_id AND r.mission_id=c.mission_id);
END $$;
CREATE FUNCTION tools_access.hub_files_confirm_846(requester text, expected_credential_version bigint,
 requested_binding uuid, expected_binding_version bigint, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text,
 requested_mission text, requested_root text, requested_calls uuid[], expected_operations uuid[])
RETURNS TABLE(credential_version bigint, binding_id uuid, binding_version bigint,
 credential_expires_at timestamptz, binding_expires_at timestamptz, activity_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE; binding tools_access.hub_actor_bindings%ROWTYPE;
 stamp timestamptz; retained bigint;
BEGIN
 IF requested_calls IS NULL OR cardinality(requested_calls) NOT BETWEEN 1 AND 64
 OR cardinality(expected_operations) IS DISTINCT FROM cardinality(requested_calls)
 OR array_ndims(requested_calls)<>1 OR array_ndims(expected_operations)<>1
 OR array_position(requested_calls,NULL) IS NOT NULL
 THEN RAISE EXCEPTION 'current hub file access refused' USING ERRCODE='42501'; END IF;
 SELECT c.* INTO actor FROM tools_access.access_credentials c WHERE c.token_hash=requester FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'current hub file access refused' USING ERRCODE='42501'; END IF;
 SELECT b.* INTO binding FROM tools_access.hub_actor_bindings b WHERE b.id=requested_binding FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'current hub file access refused' USING ERRCODE='42501'; END IF;
 -- FOR SHARE jusqu'au COMMIT : le FOR UPDATE de mission_retirement_prepare attend.
 PERFORM c.id FROM tools_access.activity_calls c WHERE c.id=ANY(requested_calls) ORDER BY c.id FOR SHARE;
 SELECT count(*) INTO retained
 FROM tools_access.activity_calls c JOIN unnest(requested_calls,expected_operations) q(call_id,operation_id)
 ON c.id=q.call_id AND c.operation_id IS NOT DISTINCT FROM q.operation_id
 WHERE c.actor_id=actor.actor_id AND c.tenant_id=actor.tenant_id AND c.service_id=actor.service_id
 AND c.mission_id=requested_mission AND c.root_agent_id=requested_root
 AND c.tool='files' AND c.category='mission' AND c.admission='admitted'
 AND NOT EXISTS(SELECT 1 FROM tools_access.mission_retirements_846 r
  WHERE r.tenant_id=c.tenant_id AND r.mission_id=c.mission_id);
 stamp:=clock_timestamp();
 IF expected_credential_version IS NULL OR actor.version<>expected_credential_version
 OR expected_binding_version IS NULL OR binding.version<>expected_binding_version
 OR actor.revoked_at IS NOT NULL OR binding.revoked_at IS NOT NULL
 OR actor.permissions<>ARRAY['hub_read']::text[] OR NOT ('files'=ANY(actor.tool_ids))
 OR (actor.expires_at IS NOT NULL AND actor.expires_at<=stamp) OR binding.expires_at<=stamp
 OR retained<>cardinality(requested_calls)
 OR ROW(binding.actor_id,binding.tenant_id,binding.service_id)
    IS DISTINCT FROM ROW(actor.actor_id,actor.tenant_id,actor.service_id)
 OR ROW(binding.issuer,binding.subject,binding.owner_id,binding.tenant_id)
    IS DISTINCT FROM ROW(requested_issuer,requested_subject,requested_owner,requested_tenant)
 THEN RAISE EXCEPTION 'current hub file access refused' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT actor.version,binding.id,binding.version,actor.expires_at,binding.expires_at,NULL::timestamptz;
END $$;
CREATE FUNCTION tools_access.purge_expired_846(requested_limit integer) RETURNS TABLE(calls bigint,events bigint,credentials bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ids uuid[]; hashes text[]; stamp timestamptz:=clock_timestamp();
BEGIN
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'invalid purge bound'; END IF;
 -- Calls techniques seulement : un call mission ne part que par mission_retirement_batch.
 SELECT array_agg(target.id) INTO ids FROM (SELECT c.id FROM tools_access.activity_calls c
 WHERE c.category='technical' AND c.expires_at<=stamp ORDER BY c.expires_at,c.id LIMIT requested_limit FOR UPDATE SKIP LOCKED) target;
 DELETE FROM tools_access.activity_events e WHERE e.call_id=ANY(ids); GET DIAGNOSTICS events=ROW_COUNT;
 DELETE FROM tools_access.activity_calls c WHERE c.id=ANY(ids); GET DIAGNOSTICS calls=ROW_COUNT;
 SELECT array_agg(target.token_hash) INTO hashes FROM (SELECT c.token_hash FROM tools_access.access_credentials c
 WHERE c.expires_at<=stamp ORDER BY c.expires_at,c.token_hash LIMIT requested_limit FOR UPDATE SKIP LOCKED) target;
 DELETE FROM tools_access.access_credentials c WHERE c.token_hash=ANY(hashes); GET DIAGNOSTICS credentials=ROW_COUNT;
 RETURN NEXT;
END $$;
CREATE FUNCTION tools_access.retirement_846_result(r tools_access.mission_retirements_846) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('operation_id',r.operation_id,'state',r.state,'claim_sha256',r.claim_sha256,
  'calls',r.calls,'events',r.events,'calls_sha256',r.calls_sha256,'events_sha256',r.events_sha256,
  'sealed_at',r.sealed_at)
$$;
CREATE FUNCTION tools_access.mission_retirement_prepare(requested_operation uuid, requested_tenant text,
 requested_mission text, requested_root text, requested_claim uuid, requested_revision bigint,
 requested_claim_sha256 text, requested_retain timestamptz, proof_expires timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r tools_access.mission_retirements_846%ROWTYPE; latest timestamptz; pending bigint;
BEGIN
 IF requested_operation IS NULL OR requested_claim IS NULL OR requested_retain IS NULL
 OR proof_expires IS NULL OR proof_expires<=clock_timestamp() THEN RAISE EXCEPTION 'retention proof expired or incomplete'; END IF;
 PERFORM pg_advisory_xact_lock(@LOCK_REQ@);
 SELECT x.* INTO r FROM tools_access.mission_retirements_846 x
 WHERE x.tenant_id=requested_tenant AND x.mission_id=requested_mission;
 IF FOUND THEN
  IF r.operation_id<>requested_operation THEN RAISE EXCEPTION 'retention scope bound to another operation'; END IF;
  IF ROW(r.root_agent_id,r.claim_id,r.claim_revision,r.claim_sha256,r.retain_until)
  IS DISTINCT FROM ROW(requested_root,requested_claim,requested_revision,requested_claim_sha256,requested_retain)
  THEN RAISE EXCEPTION 'retention claim differs'; END IF;
  RETURN tools_access.retirement_846_result(r);
 END IF;
 PERFORM 1 FROM tools_access.activity_calls c WHERE c.tenant_id=requested_tenant
 AND c.mission_id=requested_mission ORDER BY c.id FOR UPDATE;
 -- Root vide ou autre root sur le même scope : aucun retrait, l'état reste protégé.
 IF EXISTS(SELECT 1 FROM tools_access.activity_calls c WHERE c.tenant_id=requested_tenant
  AND c.mission_id=requested_mission AND c.root_agent_id IS DISTINCT FROM requested_root)
 THEN RAISE EXCEPTION 'retention scope has another root'; END IF;
 SELECT max(c.expires_at),count(*) INTO latest,pending FROM tools_access.activity_calls c
 WHERE c.tenant_id=requested_tenant AND c.mission_id=requested_mission;
 IF clock_timestamp()<=GREATEST(latest,requested_retain) THEN
  RETURN jsonb_build_object('operation_id',requested_operation,'state','not_yet_eligible',
   'eligible_after',GREATEST(latest,requested_retain));
 END IF;
 INSERT INTO tools_access.mission_retirements_846(operation_id,tenant_id,mission_id,root_agent_id,claim_id,
  claim_revision,claim_sha256,retain_until,state)
 VALUES(requested_operation,requested_tenant,requested_mission,requested_root,requested_claim,
  requested_revision,requested_claim_sha256,requested_retain,'prepared') RETURNING * INTO r;
 IF proof_expires<=clock_timestamp() THEN RAISE EXCEPTION 'retention proof expired'; END IF;
 RETURN tools_access.retirement_846_result(r)||jsonb_build_object('pending_calls',pending);
END $$;
CREATE FUNCTION tools_access.mission_retirement_batch(requested_operation uuid, requested_claim_sha256 text,
 proof_expires timestamptz, requested_limit integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r tools_access.mission_retirements_846%ROWTYPE; ids uuid[]; removed_calls bigint; removed_events bigint;
BEGIN
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 500
 OR proof_expires IS NULL OR proof_expires<=clock_timestamp() THEN RAISE EXCEPTION 'invalid retirement batch'; END IF;
 SELECT x.* INTO r FROM tools_access.mission_retirements_846 x WHERE x.operation_id=requested_operation;
 IF NOT FOUND OR r.claim_sha256 IS DISTINCT FROM requested_claim_sha256
 THEN RAISE EXCEPTION 'retirement operation unknown or claim differs'; END IF;
 PERFORM pg_advisory_xact_lock(@LOCK_ROW@);
 SELECT x.* INTO r FROM tools_access.mission_retirements_846 x WHERE x.operation_id=requested_operation FOR UPDATE;
 IF r.state='sealed' THEN
  RETURN tools_access.retirement_846_result(r)||jsonb_build_object('has_more',false,'retired_calls',0,'retired_events',0);
 END IF;
 SELECT array_agg(t.id) INTO ids FROM (SELECT c.id FROM tools_access.activity_calls c
 WHERE c.tenant_id=r.tenant_id AND c.mission_id=r.mission_id AND c.root_agent_id=r.root_agent_id
 ORDER BY c.id LIMIT requested_limit FOR UPDATE) t;
 WITH gone AS (DELETE FROM tools_access.activity_events e WHERE e.call_id=ANY(ids) RETURNING e.id)
 INSERT INTO tools_access.mission_retired_refs_846(operation_id,kind,ref_id) SELECT requested_operation,'event',gone.id FROM gone;
 GET DIAGNOSTICS removed_events=ROW_COUNT;
 WITH gone AS (DELETE FROM tools_access.activity_calls c WHERE c.id=ANY(ids) RETURNING c.id)
 INSERT INTO tools_access.mission_retired_refs_846(operation_id,kind,ref_id) SELECT requested_operation,'call',gone.id FROM gone;
 GET DIAGNOSTICS removed_calls=ROW_COUNT;
 -- Dernier lot : le scellé est écrit dans la même transaction que le dernier DELETE.
 IF NOT EXISTS(SELECT 1 FROM tools_access.activity_calls c WHERE c.tenant_id=r.tenant_id AND c.mission_id=r.mission_id) THEN
  UPDATE tools_access.mission_retirements_846 x SET state='sealed',sealed_at=clock_timestamp(),
   calls=(SELECT count(*) FROM tools_access.mission_retired_refs_846 f WHERE f.operation_id=requested_operation AND f.kind='call'),
   events=(SELECT count(*) FROM tools_access.mission_retired_refs_846 f WHERE f.operation_id=requested_operation AND f.kind='event'),
   calls_sha256=@DIGEST_CALL@, events_sha256=@DIGEST_EVENT@
  WHERE x.operation_id=requested_operation RETURNING * INTO r;
 END IF;
 IF proof_expires<=clock_timestamp() THEN RAISE EXCEPTION 'retention proof expired'; END IF;
 RETURN tools_access.retirement_846_result(r)||jsonb_build_object('has_more',r.state='prepared',
  'retired_calls',removed_calls,'retired_events',removed_events);
END $$;
CREATE FUNCTION tools_access.mission_retirement_status(requested_operation uuid, requested_tenant text,
 requested_mission text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r tools_access.mission_retirements_846%ROWTYPE; remaining bigint;
BEGIN
 -- Même verrou que prepare et batch, pris avant toute lecture : pas d'absence lue pendant un COMMIT.
 PERFORM pg_advisory_xact_lock(@LOCK_REQ@);
 SELECT count(*) INTO remaining FROM tools_access.activity_calls c
 WHERE c.tenant_id=requested_tenant AND c.mission_id=requested_mission;
 SELECT x.* INTO r FROM tools_access.mission_retirements_846 x
 WHERE x.tenant_id=requested_tenant AND x.mission_id=requested_mission;
 IF NOT FOUND THEN
  RETURN jsonb_build_object('operation_id',requested_operation,'state','absent','remaining_calls',remaining);
 END IF;
 IF r.operation_id<>requested_operation THEN RAISE EXCEPTION 'retention scope bound to another operation'; END IF;
 RETURN tools_access.retirement_846_result(r)||jsonb_build_object('remaining_calls',remaining);
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA tools_access FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tools_access FROM PUBLIC;
'''.replace('@LOCK_NEW@', _LOCK.format(t='NEW.tenant_id', m='NEW.mission_id')).replace(
    '@LOCK_REQ@', _LOCK.format(t='requested_tenant', m='requested_mission')).replace(
    '@LOCK_ROW@', _LOCK.format(t='r.tenant_id', m='r.mission_id')).replace(
    '@DIGEST_CALL@', _DIGEST.format(kind='call')).replace('@DIGEST_EVENT@', _DIGEST.format(kind='event'))
CHECKSUM = hashlib.sha256(DDL.encode()).hexdigest()

FUNCTIONS = ('guard_retirement_846', 'guard_mission_admission_846', 'guard_mission_delete_846',
             'retention_846_contract', 'activity_page_846', 'hub_activity_page_846', 'hub_file_calls_846',
             'hub_files_confirm_846', 'purge_expired_846', 'retirement_846_result',
             'mission_retirement_prepare', 'mission_retirement_batch', 'mission_retirement_status')
TABLES = ('retention_846_version', 'mission_retirements_846', 'mission_retired_refs_846')
# v1 -> 846. Les routines v1 restent dans le schéma, accordées à personne.
REPLACED = {
    'activity_page(text,timestamptz,uuid,integer)': 'activity_page_846(text,timestamptz,uuid,integer)',
    'hub_activity_page(text,text,text,text,text,text,text,timestamptz,uuid,integer)':
        'hub_activity_page_846(text,text,text,text,text,text,text,timestamptz,uuid,integer)',
    'hub_file_calls(text,text,text,text,text,text,text,uuid[])':
        'hub_file_calls_846(text,text,text,text,text,text,text,uuid[])',
    'hub_files_confirm(text,bigint,uuid,bigint,text,text,text,text,text,text,uuid[],uuid[])':
        'hub_files_confirm_846(text,bigint,uuid,bigint,text,text,text,text,text,text,uuid[],uuid[])',
    'purge_expired(integer)': 'purge_expired_846(integer)',
}
_V1_APP = ("credential_get(text)", "admit_technical(uuid,text,text,uuid,uuid)",
           "finish_activity(uuid,text)") + ADMIN_ROUTINES + LOOKUP_ROUTINES + HUB_ROUTINES
APP_ROUTINES = tuple(REPLACED.get(name, name) for name in _V1_APP) + ('retention_846_contract()',)
MAINTENANCE_ROUTINES = ('purge_expired_846(integer)', 'retention_846_contract()',
    'mission_retirement_prepare(uuid,text,text,text,uuid,bigint,text,timestamptz,timestamptz)',
    'mission_retirement_batch(uuid,text,timestamptz,integer)',
    'mission_retirement_status(uuid,text,text)')


def routine_profile(retention):
    """Routines exécutables et tables sans droit direct, par profil."""
    from .postgres_schema import APP_ROUTINES as V1_APP, MAINTENANCE_ROUTINES as V1_MAINTENANCE
    base = ('schema_version', 'hub_actor_bindings', 'access_credentials', 'activity_calls', 'activity_events')
    if not retention:
        return V1_APP, V1_MAINTENANCE, base
    return APP_ROUTINES, MAINTENANCE_ROUTINES, base + TABLES


def function_sources():
    """Corps attendus de chaque fonction 846 (prosrc), extraits du DDL rendu."""
    sources = {}
    for name in FUNCTIONS:
        start = DDL.index('CREATE FUNCTION tools_access.' + name + '(')
        start = DDL.index('$$', start) + 2
        sources[name] = DDL[start:DDL.index('$$', start)]
    return sources


# Projection catalogue attendue sous search_path=pg_catalog, observée sur PG17 par le
# kit j0/run846-dep-r3 (access_846_catalog.observed.json). Tris en COLLATE "C".
_T = 'tools_access.'
CATALOG = {
    'triggers': [
        {'relname': 'activity_calls', 'tgname': 'immutable_calls', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER immutable_calls BEFORE UPDATE ON ' + _T + 'activity_calls FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_history()'},
        {'relname': 'activity_calls', 'tgname': 'retention_846_admission', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER retention_846_admission BEFORE INSERT ON ' + _T + 'activity_calls FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_mission_admission_846()'},
        {'relname': 'activity_calls', 'tgname': 'retention_846_delete', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER retention_846_delete BEFORE DELETE ON ' + _T + 'activity_calls FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_mission_delete_846()'},
        {'relname': 'mission_retired_refs_846', 'tgname': 'retired_refs_846_append', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER retired_refs_846_append BEFORE DELETE OR UPDATE ON ' + _T + 'mission_retired_refs_846 FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_history()'},
        {'relname': 'mission_retirements_846', 'tgname': 'retirement_846_identity', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER retirement_846_identity BEFORE DELETE OR UPDATE ON ' + _T + 'mission_retirements_846 FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_retirement_846()'},
        {'relname': 'retention_846_version', 'tgname': 'retention_846_immutable', 'tgenabled': 'O', 'definition':
         'CREATE TRIGGER retention_846_immutable BEFORE DELETE OR UPDATE ON ' + _T + 'retention_846_version FOR EACH ROW EXECUTE FUNCTION ' + _T + 'guard_history()'},
    ],
    'constraints': [
        {'relname': 'mission_retired_refs_846', 'conname': 'mission_retired_refs_846_kind_check', 'contype': 'c',
         'definition': "CHECK ((kind = ANY (ARRAY['call'::text, 'event'::text])))"},
        {'relname': 'mission_retired_refs_846', 'conname': 'mission_retired_refs_846_operation_id_fkey', 'contype': 'f',
         'definition': 'FOREIGN KEY (operation_id) REFERENCES ' + _T + 'mission_retirements_846(operation_id)'},
        {'relname': 'mission_retired_refs_846', 'conname': 'mission_retired_refs_846_pkey', 'contype': 'p',
         'definition': 'PRIMARY KEY (operation_id, kind, ref_id)'},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_check', 'contype': 'c',
         'definition': "CHECK (((state = 'sealed'::text) = (sealed_at IS NOT NULL)))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_claim_revision_check', 'contype': 'c',
         'definition': 'CHECK ((claim_revision > 0))'},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_claim_sha256_check', 'contype': 'c',
         'definition': "CHECK ((claim_sha256 ~ '^[0-9a-f]{64}$'::text))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_mission_id_check', 'contype': 'c',
         'definition': "CHECK ((mission_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_pkey', 'contype': 'p',
         'definition': 'PRIMARY KEY (operation_id)'},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_root_agent_id_check', 'contype': 'c',
         'definition': "CHECK (((root_agent_id = ''::text) OR (root_agent_id ~ '^ag_[A-Za-z0-9_-]+$'::text)))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_state_check', 'contype': 'c',
         'definition': "CHECK ((state = ANY (ARRAY['prepared'::text, 'sealed'::text])))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_tenant_id_check', 'contype': 'c',
         'definition': "CHECK ((tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))"},
        {'relname': 'mission_retirements_846', 'conname': 'mission_retirements_846_tenant_id_mission_id_key', 'contype': 'u',
         'definition': 'UNIQUE (tenant_id, mission_id)'},
        {'relname': 'retention_846_version', 'conname': 'retention_846_version_coordination_required_check', 'contype': 'c',
         'definition': 'CHECK (coordination_required)'},
        {'relname': 'retention_846_version', 'conname': 'retention_846_version_pkey', 'contype': 'p',
         'definition': 'PRIMARY KEY (singleton)'},
        {'relname': 'retention_846_version', 'conname': 'retention_846_version_singleton_check', 'contype': 'c',
         'definition': 'CHECK (singleton)'},
        {'relname': 'retention_846_version', 'conname': 'retention_846_version_version_check', 'contype': 'c',
         'definition': 'CHECK ((version = 1))'},
    ],
    'indexes': [
        {'relname': 'mission_retired_refs_846', 'definition':
         'CREATE UNIQUE INDEX mission_retired_refs_846_pkey ON ' + _T + 'mission_retired_refs_846 USING btree (operation_id, kind, ref_id)'},
        {'relname': 'mission_retirements_846', 'definition':
         'CREATE UNIQUE INDEX mission_retirements_846_pkey ON ' + _T + 'mission_retirements_846 USING btree (operation_id)'},
        {'relname': 'mission_retirements_846', 'definition':
         'CREATE UNIQUE INDEX mission_retirements_846_tenant_id_mission_id_key ON ' + _T + 'mission_retirements_846 USING btree (tenant_id, mission_id)'},
        {'relname': 'retention_846_version', 'definition':
         'CREATE UNIQUE INDEX retention_846_version_pkey ON ' + _T + 'retention_846_version USING btree (singleton)'},
    ],
    'functions': [
        {'proname': name, 'prosecdef': name not in ('guard_retirement_846', 'retirement_846_result'),
         'proconfig': ['search_path=pg_catalog']} for name in sorted(FUNCTIONS)
    ],
}
