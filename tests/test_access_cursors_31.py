"""Aucun hash ou droit n'est déduit d'un curseur public de pagination."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth.access_cursors import AccessCursors


def test_opaque_cursor_is_bound_to_reader_version_and_filters():
    cache = AccessCursors()
    binding = ('reader', 'tenant', 1, 'credentials', 50)
    cursor = cache.issue(binding, 'a'*64)
    assert 'a'*64 not in cursor
    assert cache.resolve(cursor, binding) == 'a'*64
    for changed in [('other', 'tenant', 1, 'credentials', 50),
                    ('reader', 'other', 1, 'credentials', 50),
                    ('reader', 'tenant', 2, 'credentials', 50),
                    ('reader', 'tenant', 1, 'activity', 50),
                    ('reader', 'tenant', 1, 'credentials', 100)]:
        with pytest.raises(ValueError):
            cache.resolve(cursor, changed)


def test_expiry_is_absolute_and_lru_capacity_and_restart_refuse_old_cursor():
    now = [10]
    cache = AccessCursors(ttl=5, capacity=2, clock=lambda: now[0])
    old = cache.issue('reader', 'one')
    newer = cache.issue('reader', 'two')
    assert cache.resolve(old, 'reader') == 'one'
    cache.issue('reader', 'three')
    with pytest.raises(ValueError):
        cache.resolve(old, 'reader')
    now[0] = 14
    assert cache.resolve(newer, 'reader') == 'two'
    now[0] = 15
    with pytest.raises(ValueError):
        cache.resolve(newer, 'reader')
    with pytest.raises(ValueError):
        AccessCursors().resolve(newer, 'reader')
