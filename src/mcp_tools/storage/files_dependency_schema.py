"""#846 Mission file dependencies, rendered only on top of the #845 extension.

No runtime DDL. The app inserts a dependency; the owner trigger alone checks
that the served generation is still live, under the refs row then the 845 pin
lock (same order as publish). Only maintenance retires rows, never DELETE.

Lock order per callsite (refs row, then pin advisory 'files-recovery:[key,version]'):
- dependency acquisition (guard_file_dependency): refs FOR SHARE, pin lock,
  generation_visible, INSERT.
- publish delete/write (FilesService.publish): refs FOR UPDATE, then
  guard_current_ref takes the pin lock, guard_dependency_retirement refuses a
  deletion while an active dependency exists, capture_retirement (AFTER) arms 845.
- collect (FileRecovery.collect): pin lock, blob_retirements FOR UPDATE,
  referenced() sees active dependencies. No refs lock, so no cycle with acquisition.
- operation intent with sources (guard_source_intent, 845, concat or delete):
  pin lock, then refs FOR UPDATE. This
  is the reverse order of acquisition on the same pin; PostgreSQL detects the
  deadlock and aborts one transaction. Nothing is served or published by the
  aborted side, and the caller retries explicitly.
Outcome: an acquisition committed before a logical deletion blocks it; a
deletion committed first makes generation_visible false and refuses the read.
"""

DDL = r'''
CREATE TABLE {schema}.mission_file_dependencies (
 call_id uuid NOT NULL,
 generation uuid NOT NULL REFERENCES {schema}.generations(id),
 activity_operation_id uuid,
 path text NOT NULL CHECK (octet_length(path) BETWEEN 1 AND 1024),
 pin jsonb NOT NULL CHECK (jsonb_typeof(pin)='object'),
 served_revision bigint NOT NULL CHECK (served_revision>=0),
 tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{{0,127}}$'),
 mission_id text NOT NULL CHECK (mission_id ~ '^mis_[A-Za-z0-9_-]+$'),
 root_agent_id text NOT NULL CHECK (root_agent_id ~ '^ag_[A-Za-z0-9_-]+$'),
 credential_binding text,
 state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','retired')),
 acquired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz,
 revision bigint NOT NULL DEFAULT 1 CHECK (revision>=1),
 PRIMARY KEY (call_id,generation),
 CHECK ((state='retired')=(retired_at IS NOT NULL))
);
CREATE INDEX mission_file_dependencies_active_path ON {schema}.mission_file_dependencies(path)
 WHERE state='active';
CREATE INDEX mission_file_dependencies_scope ON {schema}.mission_file_dependencies(tenant_id,mission_id,root_agent_id)
 WHERE state='active';

CREATE FUNCTION {schema}.guard_file_dependency() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE served jsonb;
BEGIN
 -- refs FOR SHARE serializes with the logical retirement (refs FOR UPDATE in publish).
 PERFORM 1 FROM {schema}.refs WHERE path=NEW.path FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'dependency path is not live'; END IF;
 SELECT pin INTO served FROM {schema}.generations WHERE id=NEW.generation AND path=NEW.path;
 IF NOT FOUND OR served IS DISTINCT FROM NEW.pin THEN
  RAISE EXCEPTION 'dependency pin differs from served generation';
 END IF;
 -- Shared with GC before it arms a physical DELETE.
 PERFORM pg_advisory_xact_lock(hashtextextended('files-recovery:' ||
   jsonb_build_array(served->>'key',served->>'version_id')::text,0));
 IF NOT {schema}.generation_visible(NEW.generation) THEN
  RAISE EXCEPTION 'dependency generation is not live';
 END IF;
 NEW.state:='active'; NEW.acquired_at:=clock_timestamp(); NEW.retired_at:=NULL; NEW.revision:=1;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_file_dependency BEFORE INSERT ON {schema}.mission_file_dependencies
 FOR EACH ROW EXECUTE FUNCTION {schema}.guard_file_dependency();

CREATE FUNCTION {schema}.guard_dependency_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable mission dependency'; END IF;
 IF (NEW.call_id,NEW.generation,NEW.activity_operation_id,NEW.path,NEW.pin,NEW.served_revision,
     NEW.tenant_id,NEW.mission_id,NEW.root_agent_id,NEW.credential_binding,NEW.acquired_at)
  IS DISTINCT FROM (OLD.call_id,OLD.generation,OLD.activity_operation_id,OLD.path,OLD.pin,OLD.served_revision,
     OLD.tenant_id,OLD.mission_id,OLD.root_agent_id,OLD.credential_binding,OLD.acquired_at)
  OR OLD.state<>'active' OR NEW.state<>'retired' OR NEW.revision<>OLD.revision+1
 THEN RAISE EXCEPTION 'immutable mission dependency'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_dependency_history BEFORE UPDATE OR DELETE ON {schema}.mission_file_dependencies
 FOR EACH ROW EXECUTE FUNCTION {schema}.guard_dependency_history();

CREATE FUNCTION {schema}.guard_dependency_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 -- The refs row is locked by this UPDATE; a pending acquisition holds FOR SHARE.
 IF NEW.deleted AND NOT OLD.deleted AND EXISTS(SELECT 1 FROM {schema}.mission_file_dependencies
     WHERE path=NEW.path AND state='active') THEN
  RAISE EXCEPTION 'file has an active mission dependency';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_dependency_retirement BEFORE UPDATE ON {schema}.refs
 FOR EACH ROW EXECUTE FUNCTION {schema}.guard_dependency_retirement();

REVOKE ALL ON {schema}.mission_file_dependencies FROM PUBLIC;
REVOKE ALL ON FUNCTION {schema}.guard_file_dependency(),{schema}.guard_dependency_history(),
 {schema}.guard_dependency_retirement() FROM PUBLIC,{app};
GRANT SELECT,INSERT ON {schema}.mission_file_dependencies TO {app};
GRANT SELECT ON {schema}.mission_file_dependencies TO {maintenance};
GRANT UPDATE(state,retired_at,revision) ON {schema}.mission_file_dependencies TO {maintenance};
'''

FUNCTIONS = ('guard_file_dependency', 'guard_dependency_history', 'guard_dependency_retirement')


def render(schema, app, maintenance):
    """Only finite identifiers, rendered after the #845 extension."""
    from psycopg import sql

    if (not all(isinstance(v, str) and v for v in (schema, app, maintenance))
            or len({app, maintenance}) != 2):
        raise ValueError('separate dependency roles required')
    return sql.SQL(DDL).format(schema=sql.Identifier(schema), app=sql.Identifier(app),
                               maintenance=sql.Identifier(maintenance))
