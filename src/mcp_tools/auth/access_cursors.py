"""Curseurs opaques de pagination : état transitoire borné, jamais autorité."""
from collections import OrderedDict
import secrets
import time


class AccessCursors:
    """Une reprise de processus invalide ses curseurs ; les droits sont relus."""

    def __init__(self, *, ttl=60, capacity=1024, clock=time.monotonic):
        if type(ttl) not in (int, float) or not 1 <= ttl <= 300:
            raise ValueError('Invalid access cursor lifetime')
        if type(capacity) is not int or not 1 <= capacity <= 10000:
            raise ValueError('Invalid access cursor capacity')
        self.ttl = ttl
        self.capacity = capacity
        self.clock = clock
        self._entries = OrderedDict()

    def _prune(self):
        now = self.clock()
        for key in list(self._entries):
            if self._entries[key][0] <= now:
                del self._entries[key]

    def issue(self, binding, position):
        self._prune()
        while len(self._entries) >= self.capacity:
            self._entries.popitem(last=False)
        opaque = secrets.token_urlsafe(32)
        self._entries[opaque] = (self.clock()+self.ttl, binding, position)
        return opaque

    def resolve(self, opaque, binding):
        self._prune()
        if not isinstance(opaque, str) or len(opaque) > 128:
            raise ValueError('Access cursor invalid or expired')
        entry = self._entries.get(opaque)
        if entry is None or entry[1] != binding:
            raise ValueError('Access cursor invalid or expired')
        return entry[2]
