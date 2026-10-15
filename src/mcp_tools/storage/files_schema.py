"""Migration initiale explicite. SQL non exécuté par le runtime."""
import hashlib

VERSION = 1
# L'installateur fixe search_path après SET ROLE owner ; aucun objet public implicite.
DDL = r'''
CREATE TABLE schema_version (singleton bool PRIMARY KEY CHECK(singleton), version int NOT NULL, checksum text NOT NULL);
CREATE TABLE operations (
 id uuid PRIMARY KEY, path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 1024),
 binding text, request_digest text NOT NULL CHECK(length(request_digest)=64),
 intent_digest text NOT NULL CHECK(length(intent_digest)=64), intent jsonb NOT NULL,
 attempt uuid NOT NULL, generation uuid NOT NULL, expected_revision bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN ('INTENT_RESERVED','CONTENT_DISPATCH_ARMED','CONTENT_VERIFIED','PUBLICATION_ARMED','EFFECT_COMMITTED','BARRIER_OBSERVED')),
 publication_allowed bool NOT NULL DEFAULT true, revocation uuid,
 closed bool NOT NULL DEFAULT false, initial_confirmation text NOT NULL DEFAULT 'unknown' CHECK(initial_confirmation='unknown'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(publication_allowed = (revocation IS NULL)), CHECK(NOT closed OR NOT publication_allowed)
);
CREATE UNIQUE INDEX one_active_path ON operations(path) WHERE NOT closed;
CREATE TABLE generations (
 id uuid PRIMARY KEY, operation uuid NOT NULL UNIQUE REFERENCES operations(id),
 path text NOT NULL, pin jsonb NOT NULL, manifest jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX generations_path ON generations(path,created_at,id);
CREATE TABLE refs (
 path text PRIMARY KEY, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 generation uuid REFERENCES generations(id), operation uuid REFERENCES operations(id),
 deleted bool NOT NULL DEFAULT true, updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE receipts (
 id uuid PRIMARY KEY, operation uuid NOT NULL REFERENCES operations(id), kind text NOT NULL,
 detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX receipts_operation ON receipts(operation,created_at,id);
CREATE FUNCTION guard_operation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(OLD.id,OLD.path,OLD.binding,OLD.request_digest,OLD.intent_digest,OLD.intent,OLD.attempt,OLD.generation,OLD.expected_revision,OLD.initial_confirmation,OLD.created_at)
 IS DISTINCT FROM ROW(NEW.id,NEW.path,NEW.binding,NEW.request_digest,NEW.intent_digest,NEW.intent,NEW.attempt,NEW.generation,NEW.expected_revision,NEW.initial_confirmation,NEW.created_at)
 OR (NOT OLD.publication_allowed AND NEW.publication_allowed)
 OR (OLD.revocation IS NOT NULL AND NEW.revocation IS DISTINCT FROM OLD.revocation)
 OR (OLD.closed AND NOT NEW.closed) THEN RAISE EXCEPTION 'immutable operation history'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_operation BEFORE UPDATE ON operations FOR EACH ROW EXECUTE FUNCTION guard_operation();
'''
CHECKSUM = hashlib.sha256(DDL.encode()).hexdigest()
TABLE_PRIVILEGES = {
    "schema_version": "SELECT",
    "operations": "SELECT, INSERT, UPDATE",
    "generations": "SELECT, INSERT",
    "refs": "SELECT, INSERT, UPDATE",
    "receipts": "SELECT, INSERT",
}
