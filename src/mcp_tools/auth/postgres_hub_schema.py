"""Destinataire hub optionnel : mapping local et intersection d'accès SQL."""

HUB_DDL = r'''
CREATE FUNCTION tools_access.hub_binding_create(requester text, requested_operation uuid,
 requested_actor uuid, requested_issuer text, requested_subject text, requested_owner text,
 requested_tenant text, requested_expiry timestamptz) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE admin_actor tools_access.access_credentials%ROWTYPE; target tools_access.access_credentials%ROWTYPE;
 binding uuid:=gen_random_uuid();
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(requested_actor::text,31));
 admin_actor:=tools_access.require_admin(requester);
 SELECT c.* INTO target FROM tools_access.access_credentials c WHERE c.actor_id=requested_actor
 AND c.tenant_id=requested_tenant AND c.revoked_at IS NULL
 AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) ORDER BY c.token_hash LIMIT 1 FOR SHARE;
 IF NOT FOUND OR requested_expiry IS NULL OR requested_expiry<=clock_timestamp()
 THEN RAISE EXCEPTION 'local actor or binding expiry invalid'; END IF;
 INSERT INTO tools_access.hub_actor_bindings(id,issuer,subject,owner_id,actor_id,tenant_id,service_id,expires_at,version)
 VALUES(binding,requested_issuer,requested_subject,requested_owner,requested_actor,requested_tenant,target.service_id,requested_expiry,1);
 IF admin_actor.expires_at IS NOT NULL AND admin_actor.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'current admin required' USING ERRCODE='42501'; END IF;
 PERFORM tools_access.record_admin(admin_actor,requested_operation,'hub_binding_create',requested_actor);
 RETURN binding;
END $$;
CREATE FUNCTION tools_access.hub_binding_revoke(requester text, requested_operation uuid,
 requested_binding uuid, expected_version bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE admin_actor tools_access.access_credentials%ROWTYPE; target uuid;
BEGIN
 admin_actor:=tools_access.require_admin(requester);
 UPDATE tools_access.hub_actor_bindings SET revoked_at=clock_timestamp(),version=version+1
 WHERE id=requested_binding AND version=expected_version AND revoked_at IS NULL RETURNING actor_id INTO target;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding version conflict'; END IF;
 IF admin_actor.expires_at IS NOT NULL AND admin_actor.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'current admin required' USING ERRCODE='42501'; END IF;
 PERFORM tools_access.record_admin(admin_actor,requested_operation,'hub_binding_revoke',target);
 RETURN true;
END $$;
CREATE FUNCTION tools_access.hub_binding_list(requester text, requested_actor uuid, after_id uuid, requested_limit integer)
RETURNS SETOF tools_access.hub_actor_bindings
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM tools_access.require_admin(requester);
 IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid page'; END IF;
 RETURN QUERY SELECT b.* FROM tools_access.hub_actor_bindings b WHERE b.actor_id=requested_actor
 AND (after_id IS NULL OR b.id>after_id) ORDER BY b.id LIMIT requested_limit;
END $$;
CREATE FUNCTION tools_access.hub_binding_get(requester text, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text)
RETURNS SETOF tools_access.hub_actor_bindings
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE;
BEGIN
 SELECT c.* INTO actor FROM tools_access.access_credentials c WHERE c.token_hash=requester FOR SHARE;
 IF NOT FOUND OR actor.revoked_at IS NOT NULL
 OR NOT ('admin'=ANY(actor.permissions) OR 'access'=ANY(actor.permissions) OR actor.permissions=ARRAY['hub_read']::text[])
 OR (actor.expires_at IS NOT NULL AND actor.expires_at<=clock_timestamp())
 THEN RAISE EXCEPTION 'current local access required' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT b.* FROM tools_access.hub_actor_bindings b WHERE b.actor_id=actor.actor_id
 AND b.tenant_id=actor.tenant_id AND b.service_id=actor.service_id
 AND b.issuer=requested_issuer AND b.subject=requested_subject AND b.owner_id=requested_owner
 AND b.tenant_id=requested_tenant AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp() FOR SHARE;
END $$;
CREATE FUNCTION tools_access.admit_mission(requested_id uuid, requester text, requested_tool text,
 requested_trace uuid, requested_operation uuid, requested_issuer text, requested_subject text,
 requested_owner text, requested_tenant text, requested_mission text, requested_root text,
 requested_body text, delegation_expiry timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding tools_access.hub_actor_bindings%ROWTYPE; actor tools_access.access_credentials%ROWTYPE; stamp timestamptz;
BEGIN
 SELECT b.* INTO STRICT binding FROM tools_access.hub_binding_get(requester,requested_issuer,
 requested_subject,requested_owner,requested_tenant) b;
 SELECT c.* INTO STRICT actor FROM tools_access.access_credentials c WHERE c.token_hash=requester FOR SHARE;
 stamp:=clock_timestamp();
 IF actor.revoked_at IS NOT NULL OR (actor.expires_at IS NOT NULL AND actor.expires_at<=stamp)
 OR NOT ('admin'=ANY(actor.permissions) OR ('access'=ANY(actor.permissions) AND requested_tool=ANY(actor.tool_ids)))
 OR binding.expires_at<=stamp OR delegation_expiry IS NULL OR delegation_expiry<=stamp
 THEN RAISE EXCEPTION 'mission context refused' USING ERRCODE='42501'; END IF;
 INSERT INTO tools_access.activity_calls(id,actor_id,tenant_id,service_id,tool,trace_id,operation_id,
 mission_id,root_agent_id,request_sha256,hub_binding_id,hub_binding_version,
 category,admission,created_at,expires_at)
 VALUES(requested_id,binding.actor_id,binding.tenant_id,binding.service_id,requested_tool,requested_trace,
 requested_operation,requested_mission,requested_root,requested_body,binding.id,binding.version,
 'mission','admitted',stamp,stamp+interval '8760 hours');
 RETURN true;
END $$;
CREATE FUNCTION tools_access.hub_access_confirm(requester text, expected_credential_version bigint,
 requested_binding uuid, expected_binding_version bigint, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text)
RETURNS TABLE(credential_version bigint, binding_id uuid, binding_version bigint,
 credential_expires_at timestamptz, binding_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE; binding tools_access.hub_actor_bindings%ROWTYPE;
 stamp timestamptz;
BEGIN
 -- Les deux lignes restent verrouillées jusqu'au COMMIT de cette décision.
 -- Une attente sur le mapping ne peut donc séparer lecture des droits/version
 -- et décision finale ; toute échéance est recontrôlée après les deux locks.
 SELECT c.* INTO actor FROM tools_access.access_credentials c WHERE c.token_hash=requester FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'local access changed' USING ERRCODE='42501'; END IF;
 SELECT b.* INTO binding FROM tools_access.hub_actor_bindings b WHERE b.id=requested_binding FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'local binding changed' USING ERRCODE='42501'; END IF;
 stamp:=clock_timestamp();
 IF expected_credential_version IS NULL OR actor.version<>expected_credential_version
 OR expected_binding_version IS NULL OR binding.version<>expected_binding_version
 OR actor.revoked_at IS NOT NULL OR binding.revoked_at IS NOT NULL
 OR NOT ('admin'=ANY(actor.permissions) OR 'access'=ANY(actor.permissions) OR actor.permissions=ARRAY['hub_read']::text[])
 OR (actor.expires_at IS NOT NULL AND actor.expires_at<=stamp) OR binding.expires_at<=stamp
 OR ROW(binding.actor_id,binding.tenant_id,binding.service_id)
    IS DISTINCT FROM ROW(actor.actor_id,actor.tenant_id,actor.service_id)
 OR ROW(binding.issuer,binding.subject,binding.owner_id,binding.tenant_id)
    IS DISTINCT FROM ROW(requested_issuer,requested_subject,requested_owner,requested_tenant)
 THEN RAISE EXCEPTION 'local access or binding changed' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT actor.version,binding.id,binding.version,actor.expires_at,binding.expires_at;
END $$;
CREATE FUNCTION tools_access.hub_activity_page(requester text, requested_issuer text,
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
 c.mission_id,c.category,c.admission,c.created_at,c.expires_at,e.outcome,e.target_actor_id
 FROM tools_access.activity_calls c LEFT JOIN LATERAL
 (SELECT event.outcome,event.target_actor_id FROM tools_access.activity_events event WHERE event.call_id=c.id
 ORDER BY (event.phase='terminal') DESC LIMIT 1) e ON true
 WHERE c.actor_id=binding.actor_id AND c.tenant_id=binding.tenant_id AND c.service_id=binding.service_id
 AND ('admin'=ANY(actor.permissions) OR c.tool=ANY(actor.tool_ids))
 AND c.mission_id=requested_mission AND c.root_agent_id=requested_root AND c.expires_at>clock_timestamp()
 AND (before_stamp IS NULL OR ROW(c.created_at,c.id)<ROW(before_stamp,before_id))
 ORDER BY c.created_at DESC,c.id DESC LIMIT requested_limit;
END $$;
'''

HUB_DDL += r'''
CREATE FUNCTION tools_access.hub_file_calls(requester text, requested_issuer text,
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
 AND c.expires_at>clock_timestamp();
END $$;
'''

HUB_DDL += r'''
CREATE FUNCTION tools_access.hub_files_confirm(requester text, expected_credential_version bigint,
 requested_binding uuid, expected_binding_version bigint, requested_issuer text,
 requested_subject text, requested_owner text, requested_tenant text,
 requested_mission text, requested_root text, requested_calls uuid[], expected_operations uuid[])
RETURNS TABLE(credential_version bigint, binding_id uuid, binding_version bigint,
 credential_expires_at timestamptz, binding_expires_at timestamptz, activity_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor tools_access.access_credentials%ROWTYPE; binding tools_access.hub_actor_bindings%ROWTYPE;
 stamp timestamptz; retained bigint; deadline timestamptz;
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
 -- Retenir aussi les lignes d'activité jusqu'au COMMIT de la même décision.
 PERFORM c.id FROM tools_access.activity_calls c WHERE c.id=ANY(requested_calls) ORDER BY c.id FOR SHARE;
 SELECT count(*),min(c.expires_at) INTO retained,deadline
 FROM tools_access.activity_calls c JOIN unnest(requested_calls,expected_operations) q(call_id,operation_id)
 ON c.id=q.call_id AND c.operation_id IS NOT DISTINCT FROM q.operation_id
 WHERE c.actor_id=actor.actor_id AND c.tenant_id=actor.tenant_id AND c.service_id=actor.service_id
 AND c.mission_id=requested_mission AND c.root_agent_id=requested_root
 AND c.tool='files' AND c.category='mission' AND c.admission='admitted';
 -- Toutes les échéances sont relues après l'ensemble des attentes sur les locks.
 stamp:=clock_timestamp();
 IF expected_credential_version IS NULL OR actor.version<>expected_credential_version
 OR expected_binding_version IS NULL OR binding.version<>expected_binding_version
 OR actor.revoked_at IS NOT NULL OR binding.revoked_at IS NOT NULL
 OR actor.permissions<>ARRAY['hub_read']::text[] OR NOT ('files'=ANY(actor.tool_ids))
 OR (actor.expires_at IS NOT NULL AND actor.expires_at<=stamp) OR binding.expires_at<=stamp
 OR retained<>cardinality(requested_calls) OR deadline IS NULL OR deadline<=stamp
 OR ROW(binding.actor_id,binding.tenant_id,binding.service_id)
    IS DISTINCT FROM ROW(actor.actor_id,actor.tenant_id,actor.service_id)
 OR ROW(binding.issuer,binding.subject,binding.owner_id,binding.tenant_id)
    IS DISTINCT FROM ROW(requested_issuer,requested_subject,requested_owner,requested_tenant)
 THEN RAISE EXCEPTION 'current hub file access refused' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT actor.version,binding.id,binding.version,actor.expires_at,binding.expires_at,deadline;
END $$;
'''

HUB_ROUTINES = (
    'hub_files_confirm(text,bigint,uuid,bigint,text,text,text,text,text,text,uuid[],uuid[])',
    'hub_file_calls(text,text,text,text,text,text,text,uuid[])',
    'hub_binding_create(text,uuid,uuid,text,text,text,text,timestamptz)',
    'hub_binding_revoke(text,uuid,uuid,bigint)', 'hub_binding_list(text,uuid,uuid,integer)',
    'hub_binding_get(text,text,text,text,text)',
    'admit_mission(uuid,text,text,uuid,uuid,text,text,text,text,text,text,text,timestamptz)',
    'hub_access_confirm(text,bigint,uuid,bigint,text,text,text,text)',
    'hub_activity_page(text,text,text,text,text,text,text,timestamptz,uuid,integer)',
)
