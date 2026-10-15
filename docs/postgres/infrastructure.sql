-- Exemple opérateur PostgreSQL 17/18 pour schéma tools_files : adapter au DBaaS.
-- Exécuter exclusivement après auth Vault (profil Vault-first) sous provisionneur.
-- Aucun secret ici. Ne pas accorder pg_monitor ni les fonctions contrôle directement à app.
-- Ne modifier aucune autre base. HBA doit interdire app dans les autres bases.
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO tools_files_owner;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_checkpoint() TO tools_files_owner;
GRANT pg_read_all_stats TO tools_files_owner;
SET ROLE tools_files_owner;
CREATE TABLE tools_files.replication_identities (
 name text PRIMARY KEY, role_name text UNIQUE NOT NULL, address text UNIQUE NOT NULL,
 slot text UNIQUE NOT NULL, dn text UNIQUE NOT NULL
);
-- Roster rempli explicitement par opérateur, cert DN/rôle/host/slot distincts.
-- HBA hostssl replication <role> <address> cert clientcert=verify-full ; rôle par membre,
-- certificats/slots exclusifs et accès non autorisés interdits. Aucune preuve HBA automatique ici.
CREATE FUNCTION tools_files.files_infrastructure() RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $function$
 SELECT jsonb_build_object(
   'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
   'timeline',(SELECT timeline_id FROM pg_control_checkpoint()),
   'recovery',pg_is_in_recovery(), 'fsync',current_setting('fsync')='on',
   'standby_names',current_setting('synchronous_standby_names'),
   'members',COALESCE((SELECT jsonb_agg(jsonb_build_object(
     'name',r.application_name,'role',r.usename,'address',r.client_addr::text,
     'slot',slot.slot_name,'dn',tls.client_dn,'pid',r.pid,'state',r.state,
     'sync_state',r.sync_state,'replay_lsn',r.replay_lsn::text,
     'authenticated',tls.ssl AND tls.client_dn=i.dn))
     FROM pg_stat_replication r JOIN pg_stat_ssl tls ON tls.pid=r.pid
     JOIN pg_replication_slots slot ON slot.active_pid=r.pid
     JOIN tools_files.replication_identities i ON i.name=r.application_name
       AND i.role_name=r.usename AND i.address=r.client_addr::text
       AND i.slot=slot.slot_name AND i.dn=tls.client_dn), '[]'::jsonb)
 );
$function$;
REVOKE ALL ON tools_files.replication_identities FROM PUBLIC, tools_files_app;
REVOKE ALL ON FUNCTION tools_files.files_infrastructure() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tools_files.files_infrastructure() TO tools_files_app;
RESET ROLE;
