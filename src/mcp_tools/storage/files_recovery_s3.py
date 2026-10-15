"""Exact-version operator I/O; never routed from the ordinary files tool.

The caller must persist delete_armed under the domain lease and schema guard
before dispatch. A lost DELETE result is reconciled by absence(), never replayed.
"""
import hashlib
import re

from .files_credentials import StorageUnavailable
from .files_s3 import MAX_BYTES, Blobs


class RecoveryBlobs:
    def __init__(self, settings):
        self.io = Blobs(settings)

    def checked(self, pin):
        if (not isinstance(pin, dict) or not isinstance(pin.get('key'), str)
                or not re.fullmatch(re.escape(self.io.prefix) +
                                    r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', pin['key'])
                or not isinstance(pin.get('version_id'), str) or pin['version_id'] in ('', 'null')
                or not isinstance(pin.get('sha256'), str)
                or not re.fullmatch('[a-f0-9]{64}', pin['sha256'])
                or type(pin.get('size')) is not int or not 0 <= pin['size'] <= MAX_BYTES):
            raise StorageUnavailable('Recovery pin outside the owned file domain')
        return dict(pin)

    def _read(self, pin):
        result = self.io.clients[self.io.data_signature].get_object(
            Bucket=self.io.bucket, Key=pin['key'], VersionId=pin['version_id'])
        body = result['Body']
        try:
            content = body.read(pin['size'] + 1)
        finally:
            body.close()
        if (result.get('VersionId') != pin['version_id'] or len(content) != pin['size']
                or hashlib.sha256(content).hexdigest() != pin['sha256']):
            raise StorageUnavailable('Recovery content differs from the owned pin')
        return content

    async def read(self, pin):
        pin = self.checked(pin)
        return await self.io.run(lambda: self._read(pin), authorize=False)

    def _absent(self, pin):
        from botocore.exceptions import ClientError
        try:
            self._read(pin)
        except ClientError as exc:
            # Refusal, generic HTTP404, timeout and truncated bodies prove nothing.
            if exc.response.get('Error', {}).get('Code') in ('NoSuchKey', 'NoSuchVersion'):
                return True
            raise
        return False

    async def absence(self, pin):
        """Observation only after an armed/unknown DELETE; no S3 mutation."""
        pin = self.checked(pin)
        return await self.io.run(lambda: self._absent(pin), authorize=False)

    async def delete_once(self, pin):
        """One dispatch after a known SQL arm ACK, never an unknown retry."""
        pin = self.checked(pin)

        def dispatch():
            self._read(pin)
            self.io.clients[self.io.data_signature].delete_object(
                Bucket=self.io.bucket, Key=pin['key'], VersionId=pin['version_id'])
            if not self._absent(pin):
                raise StorageUnavailable('Physical deletion not confirmed')
            return True

        # Blobs keeps its slot until the real worker ends even after cancellation.
        return await self.io.run(dispatch, authorize=False)
