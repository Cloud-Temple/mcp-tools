"""Finite #845 extension, rendered only by the new-domain operator.

No runtime DDL or permission to install. The exact projection must be composed
and verified before enabling this extension or any physical collection.
"""

DDL = r'''
CREATE TABLE {schema}.blob_retirements (
 generation uuid PRIMARY KEY REFERENCES {schema}.generations(id),
 path text NOT NULL,
 pin jsonb NOT NULL CHECK (jsonb_typeof(pin)='object'),
 retired_at timestamptz NOT NULL,
 retired_ack_at timestamptz,
 recover_until timestamptz NOT NULL,
 delete_state text NOT NULL DEFAULT 'retained'
   CHECK (delete_state IN ('retained','delete_armed','deleted')),
 delete_ack_at timestamptz,
 CHECK (pin ?& ARRAY['version_id','key','sha256','size']),
 CHECK (jsonb_typeof(pin->'version_id')='string' AND pin->>'version_id' NOT IN ('','null')),
 CHECK (jsonb_typeof(pin->'key')='string' AND pin->>'key'={prefix} || generation::text),
 CHECK (jsonb_typeof(pin->'sha256')='string' AND length(pin->>'sha256')=64
   AND pin->>'sha256' ~ '^[a-f0-9]+$'),
 CHECK (jsonb_typeof(pin->'size')='number' AND (pin->>'size')::numeric>=0
   AND (pin->>'size')::numeric=trunc((pin->>'size')::numeric)),
 CHECK (recover_until >= retired_at+interval '30 days'),
 CHECK (retired_ack_at IS NULL OR recover_until >= retired_ack_at+interval '30 days'),
 CHECK (delete_state='retained' OR retired_ack_at IS NOT NULL),
 CHECK ((delete_state='deleted')=(delete_ack_at IS NOT NULL))
);
CREATE FUNCTION {schema}.guard_retirement() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable retirement anchor'; END IF;
 IF (NEW.generation,NEW.path,NEW.pin,NEW.retired_at) IS DISTINCT FROM
    (OLD.generation,OLD.path,OLD.pin,OLD.retired_at)
 OR NEW.recover_until<OLD.recover_until
 OR (OLD.retired_ack_at IS NOT NULL AND
    (NEW.retired_ack_at,NEW.recover_until) IS DISTINCT FROM (OLD.retired_ack_at,OLD.recover_until))
 OR (OLD.delete_state='retained' AND NEW.delete_state='deleted')
 OR (OLD.delete_state='delete_armed' AND NEW.delete_state='retained')
 OR (OLD.delete_state='deleted' AND
    (NEW.delete_state,NEW.delete_ack_at) IS DISTINCT FROM (OLD.delete_state,OLD.delete_ack_at))
 THEN RAISE EXCEPTION 'immutable retired pin'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_retirement BEFORE UPDATE OR DELETE ON {schema}.blob_retirements
 FOR EACH ROW EXECUTE FUNCTION {schema}.guard_retirement();

CREATE FUNCTION {schema}.capture_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE retired timestamptz;
BEGIN
 IF NEW.deleted AND NOT OLD.deleted THEN
  retired:=clock_timestamp();
  INSERT INTO {schema}.blob_retirements(generation,path,pin,retired_at,recover_until)
   SELECT id,path,pin,retired,retired+{days}*interval '1 day' FROM {schema}.generations
   WHERE path=NEW.path ON CONFLICT(generation) DO NOTHING;
 ELSIF NOT NEW.deleted AND EXISTS(
    SELECT 1 FROM {schema}.blob_retirements WHERE generation=NEW.generation) THEN
  RAISE EXCEPTION 'retired generation cannot be republished';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER capture_retirement AFTER UPDATE ON {schema}.refs
 FOR EACH ROW EXECUTE FUNCTION {schema}.capture_retirement();

CREATE FUNCTION {schema}.generation_visible(wanted uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM {schema}.generations g
  JOIN {schema}.refs r ON r.path=g.path WHERE g.id=wanted AND NOT r.deleted)
  AND NOT EXISTS(SELECT 1 FROM {schema}.blob_retirements WHERE generation=wanted)
$$;

CREATE FUNCTION {schema}.guard_source_pins() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE entry jsonb;
BEGIN
 IF jsonb_typeof(NEW.pin)<>'object'
  OR NOT (NEW.pin ?& ARRAY['key','version_id','sha256','size'])
  OR jsonb_typeof(NEW.pin->'key')<>'string'
  OR NEW.pin->>'key' IS DISTINCT FROM {prefix} || NEW.id::text
  OR jsonb_typeof(NEW.pin->'version_id')<>'string' OR NEW.pin->>'version_id' IN ('','null')
 THEN RAISE EXCEPTION 'new generation requires its own versioned key'; END IF;
 IF jsonb_typeof(NEW.manifest)<>'array' THEN RAISE EXCEPTION 'invalid source pins'; END IF;
 FOR entry IN SELECT jsonb_array_elements(NEW.manifest) LOOP
  IF NOT EXISTS(SELECT 1 FROM {schema}.generations g
      WHERE g.id=(entry->>'generation')::uuid AND g.path=entry->>'path' AND g.pin=entry->'pin') THEN
   RAISE EXCEPTION 'unknown source pin';
  END IF;
  -- Shared with GC before it arms a physical DELETE; no app table privilege.
  PERFORM pg_advisory_xact_lock(hashtextextended('files-recovery:' ||
    jsonb_build_array(entry->'pin'->>'key',entry->'pin'->>'version_id')::text,0));
  IF EXISTS(SELECT 1 FROM {schema}.blob_retirements
      WHERE pin->>'key'=entry->'pin'->>'key'
      AND pin->>'version_id'=entry->'pin'->>'version_id'
      AND delete_state IN ('delete_armed','deleted')) THEN
   RAISE EXCEPTION 'source pin collection in progress';
  END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_source_pins BEFORE INSERT ON {schema}.generations
 FOR EACH ROW EXECUTE FUNCTION {schema}.guard_source_pins();

REVOKE ALL ON {schema}.blob_retirements FROM PUBLIC,{app};
REVOKE ALL ON FUNCTION {schema}.guard_retirement(),{schema}.capture_retirement(),
 {schema}.generation_visible(uuid),{schema}.guard_source_pins() FROM PUBLIC;
REVOKE ALL ON FUNCTION {schema}.guard_retirement(),{schema}.capture_retirement(),
 {schema}.guard_source_pins() FROM {app};
GRANT EXECUTE ON FUNCTION {schema}.generation_visible(uuid) TO {app};
GRANT USAGE ON SCHEMA {schema} TO {maintenance};
GRANT SELECT ON {schema}.schema_version,{schema}.refs,{schema}.generations,{schema}.operations,{schema}.receipts,
 {schema}.blob_retirements TO {maintenance};
GRANT UPDATE(retired_ack_at,recover_until,delete_state,delete_ack_at)
 ON {schema}.blob_retirements TO {maintenance};
'''


def render(schema, app, maintenance, *, prefix, recovery_days=30):
    """Only finite identifier/literal placeholders, no SQL or grant allowlist."""
    from psycopg import sql

    if (type(recovery_days) is not int or recovery_days < 30
            or not all(isinstance(v, str) and v for v in (schema, app, maintenance, prefix))
            or prefix.startswith('_tokens/') or '_tokens/'.startswith(prefix)
            or len({app, maintenance}) != 2):
        raise ValueError('recovery domain and thirty-day minimum required')
    return sql.SQL(DDL).format(schema=sql.Identifier(schema), app=sql.Identifier(app),
                               maintenance=sql.Identifier(maintenance), days=sql.Literal(recovery_days),
                               prefix=sql.Literal(prefix))
