"""Résolution interne d'une cible admin sans publier son hash complet."""

LOOKUP_DDL = r'''
CREATE FUNCTION tools_access.schema_contract() RETURNS TABLE(version integer, checksum text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT v.version,v.checksum FROM tools_access.schema_version v WHERE v.singleton
$$;
CREATE FUNCTION tools_access.credential_target(requester text, requested_prefix text)
RETURNS SETOF tools_access.access_credentials
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM tools_access.require_admin(requester);
 IF requested_prefix IS NULL OR requested_prefix !~ '^[0-9a-f]{12}$'
 THEN RAISE EXCEPTION 'invalid access reference'; END IF;
 RETURN QUERY SELECT c.* FROM tools_access.access_credentials c
 WHERE left(c.token_hash,12)=requested_prefix ORDER BY c.token_hash LIMIT 2;
END $$;
'''
LOOKUP_ROUTINES = ('schema_contract()', 'credential_target(text,text)')
