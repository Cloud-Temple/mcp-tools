"""Raccord async explicite PG ; aucune lecture S3 ni bypass bootstrap dans ce profil."""
import asyncio
import inspect
from functools import lru_cache
import re
from uuid import UUID, uuid4

from ..config import get_settings
from .context import current_token_info, current_access_operation, check_tool_access
from .postgres_credentials import AccessCredentials
from .postgres_store import PostgresAccessStore
from .token_store import TokenStoreUnavailable


@lru_cache(maxsize=1)
def get_access_store():
    s = get_settings()
    if s.access_backend != 'postgres' or not s.access_pg_ca_file:
        raise TokenStoreUnavailable('PostgreSQL access profile incomplete')
    return PostgresAccessStore(AccessCredentials(s), ca_file=s.access_pg_ca_file,
        role=s.access_pg_role, database=s.access_pg_database, timeout=s.access_operation_timeout,
        cursor_ttl=s.access_cursor_ttl_seconds, cursor_capacity=s.access_cursor_capacity)


def current_binding():
    binding = (current_token_info.get() or {}).get('credential_binding', '')
    if not isinstance(binding, str) or not re.fullmatch(r'tools-token-v1:[0-9a-f]{64}', binding):
        raise ValueError('Current PostgreSQL access required')
    return binding.partition(':')[2]


async def refresh_access(tool=None):
    if get_settings().access_backend != 'postgres':
        return current_token_info.get()
    info = await get_access_store().authenticate_binding(current_binding())
    if info is None:
        raise ValueError('Access revoked or expired')
    current_token_info.set(info)
    if tool is not None:
        check_tool_access(tool)
    return info


async def run_durable_tool(tool, function, args, kwargs):
    """Admission avant effet, clôture confirmée ; incertitude sans replay."""
    if get_settings().access_backend != 'postgres':
        return await function(*args, **kwargs)
    store = get_access_store()
    from ..observability import get_activity_context, bind_activity
    from .hub_activity import current_hub_context
    delegation = current_hub_context.get()
    call_id = str(uuid4())
    if delegation is not None:
        if delegation.consumed or delegation.claims['tool_id'] != tool:
            raise ValueError('Delegation does not match this admission')
        delegation.consumed = True
        call_id = delegation.claims['call_id']
    try:
        trace_id = str(UUID(get_activity_context().get('trace_id', '')))
    except (ValueError, AttributeError, TypeError):
        trace_id = str(uuid4())
    operation_id = str(uuid4())
    bound = inspect.signature(function).bind_partial(*args, **kwargs)
    if tool == 'files' and 'operation_id' in inspect.signature(function).parameters:
        requested = bound.arguments.get('operation_id')
        if requested is not None:
            operation_id = str(UUID(str(requested)))
        elif (bound.arguments.get('operation') in {'write', 'concat', 'delete'}
              and get_settings().files_metadata_backend == 'postgres'):
            bound.arguments['operation_id'] = operation_id
        args, kwargs = bound.args, bound.kwargs
    bind_activity(trace_id=trace_id, call_id=call_id, operation_id=operation_id)
    binding = current_binding()
    if delegation is not None:
        await delegation.active()
        admitted = await store.admit_mission(call_id=call_id, binding=binding,
            tool=tool, trace_id=trace_id, operation_id=operation_id, claims=delegation.claims)
    else:
        admitted = await store.admit_binding(call_id=call_id, binding=binding,
                                             tool=tool, trace_id=trace_id, operation_id=operation_id)
    if not admitted:
        await store.finish(call_id, 'denied')
        return {'status': 'error', 'message': 'Access denied', 'activity_call_id': call_id}
    context = current_access_operation.set(operation_id)
    try:
        await refresh_access(tool)
        result = await function(*args, **kwargs)
    except asyncio.CancelledError:
        # L'annulation n'est jamais une preuve d'absence d'effet.
        try:
            await asyncio.shield(store.finish(call_id, 'uncertain'))
        except Exception:
            pass
        raise
    except Exception:
        try:
            await store.finish(call_id, 'failed')
        except TokenStoreUnavailable:
            return {'status': 'uncertain', 'message': 'Activity terminal not confirmed; do not replay',
                    'activity_call_id': call_id, 'operation_id': operation_id}
        raise
    finally:
        current_access_operation.reset(context)
    status = result.get('status') if isinstance(result, dict) else None
    outcome = ('uncertain' if status in {'unavailable', 'uncertain'} else
               'failed' if status in {'error', 'failed'} else 'completed')
    try:
        await store.finish(call_id, outcome)
    except TokenStoreUnavailable:
        return {'status': 'uncertain', 'message': 'Activity terminal not confirmed; do not replay',
                'activity_call_id': call_id, 'operation_id': operation_id}
    return ({**result, 'activity_call_id': call_id, 'activity_state': 'confirmed'}
            if isinstance(result, dict) else result)
