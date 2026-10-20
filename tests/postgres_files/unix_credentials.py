"""Credential/TCP-TLS boundary for the isolated Unix PG17 fixture only."""
import psycopg
from src.mcp_tools.storage.files_credentials import Credentials


def activate(socket):
    real_connect = psycopg.AsyncConnection.connect

    async def credential(self, service=None):
        return dict(host='127.0.0.1', port=5432, dbname=self.s.files_pg_database,
                    user=self.s.files_pg_role, password='fixture-only-not-a-real-secret-123456')

    async def connect(cls, *args, **kwargs):
        assert kwargs.pop('sslmode') == 'verify-full'
        assert kwargs.pop('sslrootcert')
        kwargs['host'] = str(socket)
        return await real_connect(*args, **kwargs)

    Credentials.sql = credential
    psycopg.AsyncConnection.connect = classmethod(connect)
