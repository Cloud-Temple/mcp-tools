"""Projection #31 vers le connecteur Vault public #30, lecture fraîche à chaque fois."""
from types import SimpleNamespace
import os

from ..storage.files_credentials import Credentials, StorageUnavailable
from .token_store import TokenStoreUnavailable


def access_environment_allowed():
    """Only Files file selectors may coexist with explicit Vault Access kwargs.

    Access never selects a libpq service and always supplies a nonempty Vault
    password. PGSERVICE must be absent: even an empty value selects section [].
    No environment is changed, including while Files connections are in flight.
    """
    return 'PGSERVICE' not in os.environ and not any(
        name.startswith('PG') and value and name not in ('PGSERVICEFILE', 'PGPASSFILE')
        for name, value in os.environ.items())


class AccessCredentials:
    def __init__(self, settings):
        self.expected_hosts = settings.access_pg_hosts
        self.provider = Credentials(SimpleNamespace(
            files_credentials_mode='vault', files_pg_service='',
            files_pg_database=settings.access_pg_database, files_pg_role=settings.access_pg_role,
            files_vault_url=settings.access_vault_url, files_vault_id=settings.access_vault_id,
            files_vault_path=settings.access_vault_path,
            files_vault_token_file=settings.access_vault_token_file,
            files_vault_ca_file=settings.access_vault_ca_file,
            files_connect_timeout=min(2, settings.access_operation_timeout),
        ))

    async def sql(self):
        try:
            result = await self.provider.sql()
            hosts = result['host'].split(',')
            expected = self.expected_hosts.split(',')
            if (not expected or not all(expected) or len(expected) != len(set(expected))
                    or any(part.strip() != part or not part or any(c in part for c in '/\\@')
                           for part in hosts+expected)
                    or len(hosts) != len(set(hosts)) or set(hosts) != set(expected)
                    or type(result['port']) is not int or result['port'] != 5432):
                raise TokenStoreUnavailable('Access SQL target invalid')
            return result
        except (StorageUnavailable, KeyError, TypeError, AttributeError):
            raise TokenStoreUnavailable('Access credentials unavailable') from None
