"""Scoped physical file maintenance; ordinary files/version_id keeps current ACL.

No SQL coordinates on argv, secret stdout, implicit restore, DDL or UNKNOWN retry.
"""
import argparse
import asyncio
import json
import importlib.util
import os
from pathlib import Path
import stat

from ..config import Settings
from .files_credentials import private_text
from .files_recovery import FileRecovery


class RecoverySettings(Settings):
    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings,
                                   dotenv_settings, file_secret_settings):
        return (init_settings,)


def save(path, content):
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('private owned output parent required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


async def operation(args):
    data = json.loads(private_text(str(args.profile)))
    if not isinstance(data, dict) or not set(data) <= RecoverySettings.model_fields.keys():
        raise ValueError('explicit known settings required')
    settings = RecoverySettings(_env_file=None, **data)
    if settings.files_credentials_mode != 'vault':
        raise ValueError('Vault-first recovery profile required')
    recovery = FileRecovery(settings, app_role=args.app_role)
    if args.command == 'collect':
        if not args.collection_code:
            raise ValueError('explicit reviewed physical collection provider required')
        spec = importlib.util.spec_from_file_location('pitr845_collection_control',
                                                     args.collection_code / 'collection_control.py')
        if spec is None or spec.loader is None:
            raise ValueError('physical collection provider unavailable')
        provider = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provider)
        from datetime import datetime, timezone
        return await recovery.collect(provider.PitrCollection(args), now=datetime.now(timezone.utc), batch=args.batch)
    if args.command == 'ack-retirements':

        return await recovery.acknowledge(batch=args.batch)
    if args.command in ('dependencies', 'retire-dependencies'):
        # #846 : scope Mission exact, aucun chemin ni version ; sortie privée seulement.
        scope = {'tenant_id': args.tenant_id, 'mission_id': args.mission_id,
                 'root_agent_id': args.root_agent_id, 'batch': args.batch}
        if args.command == 'dependencies':
            return await recovery.dependencies(**scope)
        return await recovery.retire_dependencies(**scope)
    if not args.path or not args.version_id or not args.output:
        raise ValueError('exact owned path/version and private output required')
    if args.command == 'inspect':
        row = await recovery.reference(path=args.path, version_id=args.version_id)
        content = json.dumps(row, default=lambda v: v.isoformat() if hasattr(v, 'isoformat') else str(v)).encode()
    else:
        content = await recovery.recover(path=args.path, version_id=args.version_id)
    save(args.output, content)
    return {'output_confirmed': True, 'ttl_reset': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('ack-retirements', 'inspect', 'recover', 'collect',
                                                'dependencies', 'retire-dependencies'))
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--app-role', required=True)
    parser.add_argument('--intent-dir', type=Path, required=True)
    parser.add_argument('--path')
    parser.add_argument('--version-id')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--batch', type=int, default=100)
    parser.add_argument('--collection-code', type=Path)
    parser.add_argument('--tenant-id')
    parser.add_argument('--mission-id')
    parser.add_argument('--root-agent-id')
    parser.add_argument('--pitr-code', type=Path)
    parser.add_argument('--pitr-domain', choices=('mission', 'teleport'))
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--stack-source', type=Path)
    parser.add_argument('--folder', type=Path)
    args = parser.parse_args()
    args.intent_dir.mkdir(mode=0o700, exist_ok=False)
    save(args.intent_dir / 'intent.json', json.dumps({'action': args.command, 'blind_replay': False}).encode())
    result = {'action': args.command, 'status': 'unknown_or_refused', 'blind_replay': False}
    try:
        observed = asyncio.run(operation(args))
        result.update(observed)
        if not observed.get('inspection_required', False):
            result['status'] = 'confirmed'
    except Exception:
        pass
    save(args.intent_dir / 'result.json', json.dumps(result).encode())
    print(json.dumps(result))
    return 0 if result['status'] == 'confirmed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
