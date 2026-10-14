"""La projection refuse l'autorité Source et les droits cibles inattendus."""
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase

from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_restore import target_roles


class Rows:
    async def fetchall(self):
        return [{"role": "copy_owner", "admin_option": False, "inherit_option": False, "set_option": True}]


class Connection:
    async def execute(self, query, params):
        return Rows()


class Catalog:
    def __init__(self, *, privileged=False, other_database=False):
        self.privileged = privileged
        self.other_database = other_database

    async def one(self, connection, query, params=()):
        if "rolcanlogin" in query:
            return {"rolcanlogin": params[0] != "copy_owner", "rolsuper": self.privileged,
                    "rolcreatedb": False, "rolcreaterole": False, "rolreplication": False, "rolbypassrls": False}
        if "datdba" in query:
            return {"owner": "copy_owner"}
        return {"bad": self.other_database if "pg_database" in query else False}


class RoleBoundary(IsolatedAsyncioTestCase):
    settings = SimpleNamespace(files_pg_owner="copy_owner", files_pg_role="copy_install")
    source = [{"rolname": "source_owner"}, {"rolname": "source_app"}]

    async def test_closed_target_contract_is_accepted(self):
        await target_roles(Catalog(), Connection(), self.settings, "copy_app", self.source)

    async def test_source_identity_cannot_be_remapped_to_itself(self):
        with self.assertRaises(StorageUnavailable):
            await target_roles(Catalog(), Connection(), self.settings, "source_app", self.source)

    async def test_privileged_target_role_is_refused(self):
        with self.assertRaises(StorageUnavailable):
            await target_roles(Catalog(privileged=True), Connection(), self.settings, "copy_app", self.source)

    async def test_connect_to_other_database_is_refused(self):
        with self.assertRaises(StorageUnavailable):
            await target_roles(Catalog(other_database=True), Connection(), self.settings, "copy_app", self.source)
