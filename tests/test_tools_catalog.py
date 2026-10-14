"""The Tools server must load its complete catalog without CyberSec."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ToolsCatalogTests(unittest.TestCase):
    def test_server_catalog_without_cybersec_imports(self):
        program = '''
import asyncio, importlib.abc, json, sys
def reject_network(event, args):
    if event in ("socket.connect", "socket.getaddrinfo"):
        raise RuntimeError("No network access during catalog import")
sys.addaudithook(reject_network)
class RejectCyberSec(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp_cybersec" or fullname.startswith("mcp_cybersec.") or fullname == "src.mcp_cybersec" or fullname.startswith("src.mcp_cybersec."):
            raise ModuleNotFoundError("CyberSec is unavailable")
sys.meta_path.insert(0, RejectCyberSec())
from src.mcp_tools.server import mcp
print(json.dumps([tool.name for tool in asyncio.run(mcp.list_tools())]))
'''
        env = {'PYTHONPATH': str(ROOT), 'PYTHONDONTWRITEBYTECODE': '1'}
        # A clean interpreter and cwd prevent cached imports and private dotenv.
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run([sys.executable, '-c', program], cwd=cwd,
                                    env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        tools = json.loads(result.stdout)
        expected = {'shell', 'network', 'http', 'perplexity_search', 'perplexity_doc',
                    'date', 'calc', 'ssh', 'files', 'token', 'system_health',
                    'system_about', 'system_activity'}
        self.assertEqual(set(tools), expected)
        self.assertEqual(len(tools), len(expected))
