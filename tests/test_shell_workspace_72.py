"""Espace /tmp de shell par session MCP (#72).

Trois niveaux :
- registre et gestionnaire avec un démon Docker simulé qui enregistre chaque commande ;
- transport HTTP réel du SDK 2.2 avec le vrai AuthMiddleware : la clé vient de la
  session validée par le SDK et du jeton validé par le middleware, jamais d'un argument ;
- Docker réel quand MCP_TOOLS_TEST_SANDBOX_IMAGE désigne l'image sandbox : les
  fichiers persistent dans une session et ne se voient pas d'une session ou d'un jeton à l'autre.
"""
import asyncio
import hashlib
import json
import logging
import os
import shutil
import socket
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest
import uvicorn
from mcp.server.mcpserver import MCPServer

from src.mcp_tools.auth import middleware as auth_middleware
from src.mcp_tools.auth.context import current_credential_sha256, current_token_info
from src.mcp_tools.config import Settings
from src.mcp_tools.tools import shell, shell_workspace

SID_A = "a" * 32
SID_B = "b" * 32
TOKENS = {
    "token-A": {"client_name": "A", "permissions": ["access"], "tool_ids": ["shell"]},
    "token-B": {"client_name": "B", "permissions": ["access"], "tool_ids": ["shell"]},
}
MiB = 1024 * 1024


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_settings(**overrides):
    values = dict(sandbox_image="mcp-tools-sandbox", shell_workspace_instance="t72",
                  shell_workspace_size_bytes=256 * MiB, shell_workspace_max_count=16,
                  shell_workspace_max_total_bytes=4096 * MiB, shell_workspace_idle_seconds=900,
                  shell_workspace_max_age_seconds=7200)
    values.update(overrides)
    return Settings(**values)


# --- démon Docker simulé ------------------------------------------------------

class FakeProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self._stdout, self._stderr = returncode, stdout, stderr

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


class BrokenClient(FakeProcess):
    """Client docker run dont la connexion au démon tombe pendant l'appel."""

    def __init__(self):
        super().__init__(1)

    async def communicate(self):
        raise ConnectionResetError("connexion au démon Docker perdue")

    def kill(self):
        pass

    async def wait(self):
        return 1


class GatedProcess(FakeProcess):
    """Client docker run d'un appel qui dure jusqu'à l'ouverture de la porte."""

    def __init__(self, docker, name, gate):
        super().__init__(0, b"ok\n", b"")
        self.docker, self.name, self.gate, self.killed = docker, name, gate, asyncio.Event()

    async def communicate(self):
        await self.gate.wait()
        self.docker.running.pop(self.name, None)
        return self._stdout, self._stderr

    def kill(self):
        # Tuer le client n'arrête pas le conteneur : seul docker kill ou rm -f le fait.
        self.killed.set()

    async def wait(self):
        await self.killed.wait()
        return -9


def shell_workspace_call_name(docker):
    return option(docker.calls[-1], "--name=")


def option(args, prefix):
    return next(a[len(prefix):] for a in args if a.startswith(prefix))


def labels(args):
    return [args[i + 1] for i, a in enumerate(args) if a == "--label"]


def mounted_volume(args):
    mount = next((a for a in args if a.startswith("--mount=")), None)
    if mount is None:
        return None
    return dict(p.split("=", 1) for p in mount[len("--mount="):].split(",") if p.startswith("src="))["src"]


class FakeDocker:
    """Enregistre les commandes docker et simule volumes, conteneurs de maintien et orphelins.

    Comme Docker, `volume rm` refuse un volume encore monté par un conteneur de maintien.
    `fail` fait échouer une opération ; `gate` suspend une opération jusqu'à son événement.
    """

    def __init__(self):
        self.commands, self.calls = [], []
        self.volumes, self.holders = {}, {}
        self.leftover_containers, self.leftover_volumes = [], []
        self.fail = set()
        self.gate = {}
        # Conteneurs d'appel encore en marche après l'arrêt de leur client : nom -> volume monté.
        self.running = {}
        # Sortie forcée de docker inspect (None : comportement de Docker).
        self.inspect_output = None
        # Le client docker run se termine mais laisse son conteneur en marche.
        self.leave_running = False
        # Le client docker run échoue en E/S pendant l'appel, conteneur en marche.
        self.client_error = False
        # Conteneurs en pause : présents, volume monté, State.Running vaut true.
        self.paused = set()
        # Avec leave_running : le conteneur d'appel resté en marche est en pause.
        self.pause_calls = False

    def mounted(self):
        return {mounted_volume(args) for args in self.holders.values()} | set(self.running.values())

    async def exec(self, *argv, **kwargs):
        assert argv[0] == "docker"
        args = list(argv[1:])
        self.commands.append(args)
        verb = args[0]
        op = " ".join(args[:2]) if verb == "volume" else verb
        if op in self.gate:
            await self.gate[op].wait()
        if args[:2] == ["volume", "create"]:
            if "volume create" in self.fail:
                return FakeProcess(1)
            self.volumes[args[-1]] = args
            return FakeProcess(0, args[-1].encode())
        if args[:2] == ["volume", "rm"]:
            name = args[2]
            if "volume rm" in self.fail or name in self.mounted():
                return FakeProcess(1)
            self.volumes.pop(name, None)
            if name in self.leftover_volumes:
                self.leftover_volumes.remove(name)
            return FakeProcess(0)
        if args[:2] == ["volume", "ls"]:
            if "volume ls" in self.fail:
                return FakeProcess(1)
            name = next((a[len("name="):] for a in args if a.startswith("name=")), None)
            if name is not None:
                found = [v for v in list(self.volumes) + self.leftover_volumes if name in v]
                return FakeProcess(0, "\n".join(found).encode())
            return FakeProcess(0, "\n".join(self.leftover_volumes).encode())
        if verb == "run" and "-d" in args:
            if "holder run" in self.fail:
                return FakeProcess(1)
            self.holders[option(args, "--name=")] = args
            return FakeProcess(0, b"id\n")
        if verb == "run":
            self.calls.append(args)
            if "launch" in self.gate:
                # Docker a démarré le conteneur, mais le lancement du client n'a pas encore rendu la main.
                self.running[option(args, "--name=")] = mounted_volume(args)
                await self.gate["launch"].wait()
            if self.client_error:
                self.running[option(args, "--name=")] = mounted_volume(args)
                return BrokenClient()
            if self.leave_running:
                self.running[option(args, "--name=")] = mounted_volume(args)
                if self.pause_calls:
                    self.paused.add(option(args, "--name="))
                return FakeProcess(0, b"ok\n", b"")
            if "call" in self.gate:
                # Le conteneur tourne tant que la porte reste fermée, même si son client est arrêté.
                name = option(args, "--name=")
                self.running[name] = mounted_volume(args)
                return GatedProcess(self, name, self.gate["call"])
            return FakeProcess(0, b"ok\n", b"")
        if verb == "inspect":
            if "inspect" in self.fail:
                return FakeProcess(1)
            if self.inspect_output is not None:
                return FakeProcess(0, self.inspect_output)
            return FakeProcess(0, b"true\n") if args[-1] in self.holders else FakeProcess(1)
        if verb == "rm":
            if "rm" in self.fail:
                return FakeProcess(1)
            for name in args[2:]:
                self.holders.pop(name, None)
                self.running.pop(name, None)
                self.paused.discard(name)
                if name in self.leftover_containers:
                    self.leftover_containers.remove(name)
            return FakeProcess(0)
        if verb == "ps":
            if "ps" in self.fail:
                return FakeProcess(1)
            names = [a[len("name=^"):-1] for a in args if a.startswith("name=^")]
            if names:
                # Comme Docker : plusieurs filtres name se cumulent en « ou ».
                present = [n for n in names if n in self.running or n in self.holders]
                statuses = [a[len("status="):] for a in args if a.startswith("status=")]
                if statuses:
                    # Plusieurs filtres status se cumulent aussi en « ou ».
                    present = [n for n in present if ("paused" if n in self.paused else "running") in statuses]
                return FakeProcess(0, "".join(n + "\n" for n in present).encode())
            volume = next((a[len("volume="):] for a in args if a.startswith("volume=")), None)
            if volume is not None:
                users = [n for n, v in self.running.items() if v == volume]
                return FakeProcess(0, "\n".join(users).encode())
            return FakeProcess(0, "\n".join(self.leftover_containers).encode())
        if verb == "kill":
            if "kill" in self.fail:
                return FakeProcess(1)
            self.running.pop(args[1], None)
            self.paused.discard(args[1])
            return FakeProcess(0)
        raise AssertionError(f"commande docker inattendue : {args}")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def unremoved_calls(monkeypatch):
    """Les retraits de conteneurs d'appel en échec sont un état du module : isolé par test."""
    monkeypatch.setattr(shell, "_UNREMOVED", set())
    monkeypatch.setattr(shell, "_RETRY_TASK", None)


@pytest.fixture
def docker(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake.exec)
    return fake


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def registry(monkeypatch, clock):
    fresh = shell_workspace.WorkspaceRegistry(clock=clock)
    monkeypatch.setattr(shell_workspace, "registry", fresh)
    return fresh


@pytest.fixture
def settings(monkeypatch):
    current = {"value": make_settings()}
    monkeypatch.setattr(shell, "get_settings", lambda: current["value"])
    return current


class FakeCtx:
    def __init__(self, headers):
        self.headers = headers


def handler():
    class Capture:
        def tool(self):
            def capture(function):
                self.function = function
                return function
            return capture
    capture = Capture()
    shell.register(capture)
    return capture.function


async def invoke(function, command="true", *, sid=SID_A, token="token-A", version=None, **kwargs):
    """Appel du vrai gestionnaire, avec le contexte qu'auraient posé le SDK et le middleware."""
    headers = {}
    if sid is not None:
        headers["mcp-session-id"] = sid
    if version is not None:
        headers["mcp-protocol-version"] = version
    info = current_token_info.set(dict(TOKENS[token]))
    credential = current_credential_sha256.set(sha(token))
    try:
        return await function(command=command, ctx=FakeCtx(headers), **kwargs)
    finally:
        current_credential_sha256.reset(credential)
        current_token_info.reset(info)


def scenario(registry, body):
    async def run():
        try:
            return await body()
        finally:
            await registry.stop()
    return asyncio.run(run())


# --- clé -----------------------------------------------------------------------

def test_key_binds_session_and_validated_credential():
    key = shell_workspace.workspace_key(SID_A, sha("token-A"))
    assert key == shell_workspace.workspace_key(SID_A, sha("token-A"))
    assert key != shell_workspace.workspace_key(SID_A, sha("token-B"))
    assert key != shell_workspace.workspace_key(SID_B, sha("token-A"))
    assert SID_A not in key and sha("token-A") not in key


@pytest.mark.parametrize("session_id,credential", [
    (None, sha("token-A")), ("", sha("token-A")), (SID_A, None), (SID_A, "token-A"), ("a b", sha("token-A")),
])
def test_key_requires_session_and_credential_digest(session_id, credential):
    assert shell_workspace.workspace_key(session_id, credential) is None


def test_key_ignores_the_authorization_header():
    """Le jeton validé par le middleware fait foi, pas un en-tête relu par l'outil."""
    token = current_credential_sha256.set(sha("token-B"))
    try:
        ctx = FakeCtx({"mcp-session-id": SID_A, "authorization": "Bearer token-A"})
        assert shell_workspace.key_from_context(ctx) == shell_workspace.workspace_key(SID_A, sha("token-B"))
    finally:
        current_credential_sha256.reset(token)


@pytest.mark.parametrize("version,expected", [(None, True), ("2025-06-18", True), ("2025-11-25", True),
                                              ("2026-07-28", False), ("1999-01-01", False)])
def test_key_only_on_the_session_routed_protocol_versions(version, expected):
    headers = {"mcp-session-id": SID_A}
    if version:
        headers["mcp-protocol-version"] = version
    token = current_credential_sha256.set(sha("token-A"))
    try:
        assert (shell_workspace.key_from_context(FakeCtx(headers)) is not None) is expected
    finally:
        current_credential_sha256.reset(token)


# --- gestionnaire : repli identique ----------------------------------------------

def expected_legacy_command(settings, network, command="true"):
    """Commande docker run de main c83748e pour un appel sans espace, recopiée à la main."""
    base = ["docker", "run", "--rm", "NAME"]
    if network:
        base += ["--network=bridge"] + [f"--dns={d.strip()}" for d in settings.sandbox_dns.split(",") if d.strip()]
        tmpfs, pids = "nosuid,nodev,size=256m", 50
    else:
        base += ["--network=none"]
        tmpfs, pids = f"noexec,nosuid,nodev,size={settings.sandbox_tmpfs_size}", settings.sandbox_pids_limit
    base += ["--read-only", f"--memory={settings.sandbox_memory}", f"--memory-swap={settings.sandbox_memory}",
             f"--cpus={settings.sandbox_cpus}", f"--pids-limit={pids}", "--cap-drop=ALL",
             "--security-opt=no-new-privileges:true", f"--tmpfs=/tmp:{tmpfs}",
             "--env=OPENBLAS_NUM_THREADS=1", "--env=OPENBLAS_MAIN_FREE=1"]
    if network:
        base += ["--env=PIP_BREAK_SYSTEM_PACKAGES=1", "--tmpfs=/home/sandbox/.local:nosuid,nodev,size=128m",
                 "--tmpfs=/home/sandbox/.cache:nosuid,nodev,size=64m"]
    return base + ["--user=sandbox:sandbox", settings.sandbox_image, "bash", "-c", command]


def anonymized(args):
    return ["docker"] + ["NAME" if a.startswith("--name=sandbox-") else a for a in args]


@pytest.mark.parametrize("network", [False, True])
@pytest.mark.parametrize("case", ["no-session", "modern-protocol", "disabled"])
def test_without_workspace_the_call_is_unchanged(docker, registry, settings, network, case):
    if case == "disabled":
        settings["value"] = make_settings(shell_workspace_max_count=0)
    function = handler()
    kwargs = {"sid": None} if case == "no-session" else {}
    if case == "modern-protocol":
        kwargs["version"] = "2026-07-28"
    result = scenario(registry, lambda: invoke(function, "ls /tmp", network=network, **kwargs))
    assert anonymized(docker.calls[0]) == expected_legacy_command(settings["value"], network, "ls /tmp")
    assert "workspace" not in result and "hint" not in result
    assert docker.volumes == {} and docker.holders == {}
    # Seuls s'ajoutent les inventaires de la purge du démarrage, filtrés sur l'instance.
    inventories = [c for c in docker.commands if c[0] != "run"]
    assert [c[:2] for c in inventories] == [["ps", "-aq"], ["volume", "ls"], ["ps", "-aq"], ["volume", "ls"]]
    assert all(f"label={shell_workspace.INSTANCE_LABEL}=t72" in c for c in inventories)


def test_without_workspace_missing_path_keeps_the_previous_hint(docker, registry, settings, monkeypatch):
    async def failing(*args, **kwargs):
        return {"status": "error", "stdout": "", "stderr": "cd: /tmp/x: No such file or directory\n",
                "returncode": 1, "sandbox": True}
    monkeypatch.setattr(shell, "_run_in_sandbox", failing)
    result = scenario(registry, lambda: invoke(handler(), "cd /tmp/x", sid=None))
    assert result["hint"] == shell.STATELESS_HINT


# --- gestionnaire : espace de session ---------------------------------------------

def test_same_session_and_token_mount_the_same_volume(docker, registry, settings):
    function = handler()

    async def body():
        first = await invoke(function, "echo x > /tmp/f")
        second = await invoke(function, "cat /tmp/f", network=True)
        return first, second
    first, second = scenario(registry, body)
    volumes = [mounted_volume(c) for c in docker.calls]
    assert volumes[0] is not None and volumes[0] == volumes[1]
    assert first["workspace"]["persistent"] and first["workspace"]["new"] is True
    assert second["workspace"]["new"] is False
    assert first["workspace"]["size_bytes"] == 159916032 and first["workspace"]["max_entries"] == 16384
    assert first["workspace"]["max_file_bytes"] == 159916032
    assert not any(a.startswith("--tmpfs=/tmp") for c in docker.calls for a in c)
    assert len(docker.volumes) == 1 and len(docker.holders) == 1


def test_other_session_or_other_token_never_share_a_volume(docker, registry, settings):
    function = handler()

    async def body():
        for sid, token in [(SID_A, "token-A"), (SID_B, "token-A"), (SID_A, "token-B"), (SID_A, "token-A")]:
            await invoke(function, sid=sid, token=token)
    scenario(registry, body)
    a1, b, a_other_token, a2 = [mounted_volume(c) for c in docker.calls]
    assert a1 == a2
    assert len({a1, b, a_other_token}) == 3
    assert len(registry.live()) == 3


def test_volume_name_does_not_derive_from_session_token_or_arguments(docker, registry, settings):
    function = handler()
    command = f"echo {SID_A} shellws-{SID_A}"
    result = scenario(registry, lambda: invoke(function, command, cwd=f"/tmp/shellws-{SID_A}"))
    volume = mounted_volume(docker.calls[0])
    for secret in (SID_A, sha("token-A"), "token-A"):
        assert secret not in volume
    assert volume == registry.live()[0].volume
    rendered = json.dumps(result)
    assert volume not in rendered and SID_A not in rendered.replace(command, "")


def test_call_mount_and_holder_are_bounded_and_unprivileged(docker, registry, settings):
    scenario(registry, lambda: invoke(handler()))
    create = next(c for c in docker.commands if c[:2] == ["volume", "create"])
    assert "o=size=159916032,nr_inodes=16384,mode=1777,nosuid,nodev,noexec" in create
    assert f"{shell_workspace.INSTANCE_LABEL}=t72" in create
    holder = next(iter(docker.holders.values()))
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                 "--user=sandbox:sandbox", "--workdir=/"):
        assert flag in holder
    mount = option(holder, "--mount=")
    assert "readonly" in mount and "volume-nocopy" in mount
    assert holder[-2:] == ["sleep", str(7200 + 30 + shell_workspace.HOLDER_MARGIN_SECONDS)]
    call = docker.calls[0]
    call_mount = option(call, "--mount=")
    assert "volume-nocopy" in call_mount
    assert '"volume-opt=o=size=159916032,nr_inodes=16384,mode=1777,nosuid,nodev,noexec"' in call_mount
    assert "--ulimit=fsize=159916032:159916032" in call
    assert f"{shell_workspace.LABEL}={shell_workspace.CALL_ROLE}" in labels(call)
    for flag in ("--read-only", "--cap-drop=ALL", "--network=none", "--user=sandbox:sandbox"):
        assert flag in call


# --- capacité --------------------------------------------------------------------

@pytest.mark.parametrize("overrides", [
    {"shell_workspace_max_count": 2},
    {"shell_workspace_max_total_bytes": 2 * 256 * MiB + MiB},
])
def test_capacity_refuses_the_call_without_running_it(docker, registry, settings, overrides):
    """Décision Root : capacité pleine, la commande ne démarre pas, ni avec un /tmp éphémère."""
    settings["value"] = make_settings(**overrides)
    function = handler()

    async def body():
        await invoke(function, sid="1" * 32)
        await invoke(function, sid="2" * 32)
        return await invoke(function, "ls", sid="3" * 32, cwd="/tmp/a")
    result = scenario(registry, body)
    assert result["status"] == "error" and result["message"] == shell.CAPACITY_MESSAGE
    assert "stdout" not in result and "returncode" not in result
    assert result["workspace"] == {"persistent": False, "reason": "capacity", "idle_seconds": 900}
    assert result["hint"] == shell.CAPACITY_HINT
    assert len(docker.calls) == 2
    assert len(registry.live()) == 2 and registry.reserved_bytes() == 2 * 256 * MiB


def test_existing_session_keeps_its_workspace_when_capacity_is_full(docker, registry, settings):
    settings["value"] = make_settings(shell_workspace_max_count=1)
    function = handler()

    async def body():
        await invoke(function, sid=SID_A)
        refused = await invoke(function, sid=SID_B)
        return refused, await invoke(function, sid=SID_A)
    refused, result = scenario(registry, body)
    assert refused["status"] == "error" and refused["workspace"]["reason"] == "capacity"
    assert result["workspace"]["persistent"] is True
    # B n'a lancé aucun conteneur : le second docker run est celui de A.
    assert len(docker.calls) == 2
    assert mounted_volume(docker.calls[0]) == mounted_volume(docker.calls[1])


def test_creation_failure_is_reported_and_cleaned(docker, registry, settings):
    docker.fail.add("holder run")
    result = scenario(registry, lambda: invoke(handler()))
    assert result["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert docker.volumes == {} and registry.live() == []
    assert result["status"] == "success"


# --- expiration et nettoyage -------------------------------------------------------

def test_idle_workspace_is_swept_then_replaced(docker, registry, settings, clock):
    function = handler()

    async def body():
        await invoke(function)
        clock.now += 899
        await registry.sweep(settings["value"])
        kept = len(docker.holders)
        clock.now += 2
        await registry.sweep(settings["value"])
        gone = (dict(docker.holders), dict(docker.volumes))
        again = await invoke(function)
        return kept, gone, again
    kept, gone, again = scenario(registry, body)
    assert kept == 1 and gone == ({}, {})
    assert again["workspace"]["new"] is True
    assert mounted_volume(docker.calls[0]) != mounted_volume(docker.calls[1])


def test_max_age_never_destroys_a_workspace_in_use(docker, registry, settings, clock):
    function = handler()
    started, release = asyncio.Event(), asyncio.Event()
    real_exec = docker.exec

    async def slow_exec(*argv, **kwargs):
        if argv[1] == "run" and "-d" not in argv:
            started.set()
            await release.wait()
        return await real_exec(*argv, **kwargs)

    async def body():
        asyncio_exec = asyncio.create_subprocess_exec
        asyncio.create_subprocess_exec = slow_exec
        try:
            call = asyncio.ensure_future(invoke(function))
            await started.wait()
            clock.now += 7201
            await registry.sweep(settings["value"])
            during = (len(docker.holders), len(docker.volumes))
            replacement = await asyncio.wait_for(asyncio.ensure_future(_second_call(function, release)), 5)
            await call
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return during, replacement
        finally:
            asyncio.create_subprocess_exec = asyncio_exec

    during, replacement = scenario(registry, body)
    assert during == (1, 1)
    assert replacement["workspace"]["new"] is True
    assert len(docker.holders) == 1 and len(registry.live()) == 1


async def _second_call(function, release):
    task = asyncio.ensure_future(invoke(function))
    await asyncio.sleep(0.05)
    release.set()
    return await task


def test_lost_holder_gives_a_new_workspace(docker, registry, settings):
    function = handler()

    async def body():
        await invoke(function)
        docker.holders.clear()
        return await invoke(function)
    result = scenario(registry, body)
    assert result["workspace"]["new"] is True and result["workspace"]["reason"] == "lost"
    assert mounted_volume(docker.calls[0]) != mounted_volume(docker.calls[1])
    assert len(docker.volumes) == 1



def test_uncertain_holder_check_keeps_the_workspace(docker, registry, settings):
    """inspect en échec et inventaire impossible : rien ne prouve la perte, l'espace et ses fichiers restent."""
    function = handler()

    async def body():
        await invoke(function)
        volume = registry.live()[0].volume
        docker.fail.update({"inspect", "ps"})
        during = await invoke(function)
        docker.fail.clear()
        after = await invoke(function)
        return volume, during, after
    volume, during, after = scenario(registry, body)
    assert during["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert mounted_volume(docker.calls[1]) is None
    assert after["workspace"]["persistent"] is True and after["workspace"]["new"] is False
    assert mounted_volume(docker.calls[2]) == volume and volume in docker.volumes
    assert not any(c[:2] == ["volume", "rm"] for c in docker.commands)


def test_holder_absent_by_inventory_is_lost(docker, registry, settings):
    """inspect en échec, inventaire réussi et vide : l'absence est confirmée."""
    function = handler()

    async def body():
        await invoke(function)
        docker.holders.clear()
        docker.fail.add("inspect")
        return await invoke(function)
    result = scenario(registry, body)
    assert result["workspace"]["new"] is True and result["workspace"]["reason"] == "lost"


def test_max_age_reached_during_the_holder_check_is_not_handed_out(docker, registry, settings, clock):
    # Inactivité plus longue que l'âge maximal : seul l'âge maximal peut expirer l'espace ici.
    settings["value"] = make_settings(shell_workspace_idle_seconds=100_000)
    function = handler()
    max_age = settings["value"].shell_workspace_max_age_seconds

    async def body():
        await invoke(function)
        old = registry.live()[0].volume
        clock.now += max_age - 1
        docker.gate["inspect"] = asyncio.Event()
        call = asyncio.ensure_future(invoke(function))
        while not any(c[0] == "inspect" for c in docker.commands):
            await asyncio.sleep(0)
        clock.now += 2
        docker.gate.pop("inspect").set()
        return old, await call
    old, result = scenario(registry, body)
    assert result["workspace"]["new"] is True and result["workspace"]["reason"] == "expired"
    assert mounted_volume(docker.calls[-1]) != old

# --- retrait confirmé : la capacité suit la mémoire réellement montée ------------------

def mounted_count(docker):
    return len(docker.mounted())


def test_delayed_removal_keeps_the_workspace_counted(docker, registry, settings, clock):
    """Pendant un retrait en cours, l'espace reste compté : jamais deux volumes montés pour un compté."""
    settings["value"] = make_settings(shell_workspace_max_count=1)
    function = handler()
    docker.gate["volume rm"] = asyncio.Event()

    async def body():
        await invoke(function, sid=SID_A)
        clock.now += 10_000
        sweep = asyncio.ensure_future(registry.sweep(settings["value"]))
        while not any(c[:2] == ["volume", "rm"] for c in docker.commands):
            await asyncio.sleep(0)
        during = await invoke(function, sid=SID_B)
        observed = (len(registry.live()), mounted_count(docker))
        docker.gate.pop("volume rm").set()
        await sweep
        after = await invoke(function, sid=SID_B)
        return during, observed, after
    during, observed, after = scenario(registry, body)
    assert during["status"] == "error" and during["workspace"]["reason"] == "capacity"
    assert observed == (1, 0)
    assert after["workspace"]["persistent"] is True
    assert len(registry.live()) == 1 == mounted_count(docker)


@pytest.mark.parametrize("failure", ["rm", "volume rm", "volume ls"])
def test_refused_removal_keeps_the_workspace_counted_until_a_retry_succeeds(docker, registry, settings, clock,
                                                                            failure):
    settings["value"] = make_settings(shell_workspace_max_count=1)
    function = handler()

    async def body():
        await invoke(function, sid=SID_A)
        clock.now += 10_000
        docker.fail.add(failure)
        await registry.sweep(settings["value"])
        refused = await invoke(function, sid=SID_B)
        counted = len(registry.live())
        docker.fail.discard(failure)
        await registry.sweep(settings["value"])
        admitted = await invoke(function, sid=SID_B)
        return refused, counted, admitted
    refused, counted, admitted = scenario(registry, body)
    assert refused["status"] == "error" and refused["workspace"]["reason"] == "capacity"
    assert counted == 1
    assert admitted["workspace"]["persistent"] is True
    assert len(registry.live()) == 1 == mounted_count(docker) == len(docker.volumes)


def test_cancelled_removal_keeps_the_workspace_counted(docker, registry, settings, clock):
    settings["value"] = make_settings(shell_workspace_max_count=1)
    function = handler()
    docker.gate["volume rm"] = asyncio.Event()

    async def body():
        await invoke(function, sid=SID_A)
        clock.now += 10_000
        sweep = asyncio.ensure_future(registry.sweep(settings["value"]))
        while not any(c[:2] == ["volume", "rm"] for c in docker.commands):
            await asyncio.sleep(0)
        sweep.cancel()
        with pytest.raises(asyncio.CancelledError):
            await sweep
        counted = len(registry.live())
        refused = await invoke(function, sid=SID_B)
        docker.gate.pop("volume rm").set()
        await registry.sweep(settings["value"])
        return counted, refused
    counted, refused = scenario(registry, body)
    assert counted == 1 and refused["status"] == "error" and refused["workspace"]["reason"] == "capacity"
    assert registry.live() == [] and docker.volumes == {}


def test_creation_timeout_keeps_the_half_created_workspace_counted(docker, registry, settings, monkeypatch):
    """Un délai dépassé sur le démarrage du maintien peut le laisser démarré : il reste compté."""
    settings["value"] = make_settings(shell_workspace_max_count=1)
    real_exec = docker.exec

    async def timing_out(*argv, **kwargs):
        process = await real_exec(*argv, **kwargs)
        if argv[1] == "run" and "-d" in argv:
            raise asyncio.TimeoutError()
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", timing_out)
    function = handler()

    async def body():
        first = await invoke(function, sid=SID_A)
        return first
    first = scenario(registry, body)
    assert first["workspace"] == {"persistent": False, "reason": "unavailable"}
    # Le retrait qui suit l'échec a confirmé l'absence du volume : plus rien n'est compté ni monté.
    assert registry.live() == [] and docker.volumes == {} and docker.holders == {}


def test_creation_timeout_with_refused_cleanup_stays_counted(docker, registry, settings, monkeypatch):
    settings["value"] = make_settings(shell_workspace_max_count=1)
    real_exec = docker.exec

    async def timing_out(*argv, **kwargs):
        process = await real_exec(*argv, **kwargs)
        if argv[1] == "run" and "-d" in argv and "rm" not in docker.fail:
            docker.fail.add("rm")
            raise asyncio.TimeoutError()
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", timing_out)
    function = handler()

    async def body():
        first = await invoke(function, sid=SID_A)
        second = await invoke(function, sid=SID_B)
        return first, second, len(registry.live()), mounted_count(docker)
    first, second, counted, mounted = scenario(registry, body)
    assert first["workspace"]["reason"] == "unavailable"
    assert second["status"] == "error" and second["workspace"]["reason"] == "capacity"
    assert counted == 1 == mounted


@pytest.mark.parametrize("failure", ["ps", "volume ls", "leftover"])
def test_uncertain_startup_inventory_suspends_admissions(docker, registry, settings, clock, failure):
    if failure == "leftover":
        docker.leftover_volumes = ["shellws-old"]
        docker.fail.add("volume rm")
    else:
        docker.fail.add(failure)
    function = handler()

    async def body():
        refused = await invoke(function, sid=SID_A)
        soon = await invoke(function, sid=SID_A)
        docker.fail.clear()
        clock.now += shell_workspace.SWEEP_INTERVAL_SECONDS
        admitted = await invoke(function, sid=SID_A)
        return refused, soon, admitted
    refused, soon, admitted = scenario(registry, body)
    assert refused["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert soon["workspace"] == {"persistent": False, "reason": "unavailable"}
    # Aucune création tant que l'inventaire est incertain : la seule a suivi la purge confirmée.
    assert sum(1 for c in docker.commands if c[:2] == ["volume", "create"]) == 1
    assert len(docker.calls) == 3
    assert admitted["workspace"]["persistent"] is True
    assert docker.leftover_volumes == []


def test_tmpfs_layout_keeps_data_and_entries_within_the_space_budget():
    for size in (MiB, 8 * MiB, 256 * MiB, 1024 * MiB + 12345):
        data, entries = shell_workspace.tmpfs_layout(size)
        assert data > 0 and entries > 0
        assert data + entries * shell_workspace.INODE_COST_BYTES <= size
    assert shell_workspace.tmpfs_layout(256 * MiB) == (159916032, 16384)


def test_tmpfs_layout_reserves_the_page_index_of_a_sparse_file():
    """Au pire, chaque page d'un fichier creux a son propre nœud à chaque niveau de l'index."""
    for size in (MiB, 8 * MiB, 256 * MiB, 4096 * MiB):
        data, entries = shell_workspace.tmpfs_layout(size)
        pages = data // shell_workspace.PAGE_BYTES
        height = shell_workspace._xarray_height(pages)
        worst = data + pages * height * shell_workspace.XARRAY_NODE_BYTES + entries * shell_workspace.INODE_COST_BYTES
        assert worst <= size


def test_workspaces_are_disabled_by_default():
    assert Settings().shell_workspace_max_count == 0


# --- réponses d'erreur et indices combinés ------------------------------------------

def test_timeout_response_keeps_the_workspace_state(docker, registry, settings, monkeypatch):
    async def timing_out(*args, **kwargs):
        raise asyncio.TimeoutError()
    monkeypatch.setattr(shell, "_run_in_sandbox", timing_out)
    result = scenario(registry, lambda: invoke(handler(), "sleep 99"))
    assert result["status"] == "error" and "Timeout" in result["message"]
    assert result["workspace"]["persistent"] is True and result["workspace"]["new"] is True


def test_timeout_response_on_ephemeral_fallback_says_so(docker, registry, settings, monkeypatch):
    docker.fail.add("volume create")

    async def timing_out(*args, **kwargs):
        raise asyncio.TimeoutError()
    monkeypatch.setattr(shell, "_run_in_sandbox", timing_out)
    result = scenario(registry, lambda: invoke(handler(), "sleep 99", cwd="/tmp/a"))
    assert result["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert result["hint"].startswith(shell.CWD_IGNORED_WORKSPACE_HINT)
    assert "éphémère" in result["hint"]


def test_cwd_hint_does_not_hide_the_ephemeral_reason(docker, registry, settings):
    docker.fail.add("volume create")
    result = scenario(registry, lambda: invoke(handler(), "ls", cwd="/tmp/a"))
    assert result["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert shell.CWD_IGNORED_WORKSPACE_HINT in result["hint"]
    assert "espace indisponible pour cet appel" in result["hint"]


def test_without_workspace_cwd_hint_is_unchanged(docker, registry, settings):
    result = scenario(registry, lambda: invoke(handler(), "ls", sid=None, cwd="/tmp/a"))
    assert result["hint"] == shell.CWD_IGNORED_HINT and "workspace" not in result


# --- annulation : réservation et conteneur d'appel ---------------------------------------

def test_replacing_an_expired_workspace_does_not_wait_for_its_removal(docker, registry, settings, clock):
    """Le retrait de l'ancien espace ne suit pas la réservation du nouveau sur le chemin de l'appel.

    Sinon une annulation pendant ce retrait perdait la réservation : `active` restait à 1.
    """
    function = handler()

    async def body():
        await invoke(function)
        clock.now += 10_000
        docker.gate["volume rm"] = asyncio.Event()
        replaced = await asyncio.wait_for(invoke(function), 2)
        active = [w.active for w in registry.live()]
        docker.gate.pop("volume rm").set()
        return replaced, active
    replaced, active = scenario(registry, body)
    assert replaced["workspace"]["new"] is True and replaced["workspace"]["reason"] == "expired"
    assert active == [0, 0]
    assert len(registry.live()) == 1 and len(docker.volumes) == 1


def _cancel_running_call(docker, registry, function, cancel):
    """Lance un appel dont le conteneur tourne, l'annule avec `cancel`, rend l'état observé."""
    docker.gate["call"] = asyncio.Event()

    async def body():
        call = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        await cancel(call)
        for _ in range(200):
            if not docker.running and all(w.active == 0 for w in registry.live()):
                break
            await asyncio.sleep(0.01)
        return dict(docker.running), [w.active for w in registry.live()]
    return scenario(registry, body)


def test_cancelled_call_removes_its_container_then_releases_the_workspace(docker, registry, settings):
    async def cancel(call):
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
    running, active = _cancel_running_call(docker, registry, handler(), cancel)
    assert running == {}
    assert active == [0]
    name = next(c for c in docker.commands if c[0] == "kill")[1]
    assert ["rm", "-f", name] in docker.commands
    assert ["ps", "-aq", "--filter", f"name=^{name}$"] in docker.commands


def test_anyio_cancellation_does_not_interrupt_the_cleanup(docker, registry, settings):
    """Le SDK annule par portée AnyIO, qui relance l'annulation à chaque attente de l'appel."""
    import anyio
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        async with anyio.create_task_group() as group:
            group.start_soon(invoke, function, "sleep 600")
            while not docker.running:
                await asyncio.sleep(0)
            group.cancel_scope.cancel()
        for _ in range(200):
            if not docker.running and all(w.active == 0 for w in registry.live()):
                break
            await asyncio.sleep(0.01)
        return dict(docker.running), [w.active for w in registry.live()]
    running, active = scenario(registry, body)
    assert running == {} and active == [0]


def test_cleanup_that_cannot_remove_the_container_is_reported(docker, registry, settings, monkeypatch):
    events = []
    monkeypatch.setattr(shell, "record_activity", lambda event, **kw: events.append(event))
    monkeypatch.setattr(shell, "CLEANUP_CHECK_INTERVAL", 0)
    docker.fail.update({"kill", "rm"})

    async def cancel(call):
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        for _ in range(200):
            if "sandbox.cleanup_failed" in events:
                break
            await asyncio.sleep(0.01)
    running, _ = _cancel_running_call(docker, registry, handler(), cancel)
    assert "sandbox.cleanup_failed" in events
    assert len(running) == 1
    name = next(iter(running))
    checks = [c for c in docker.commands if c == ["ps", "-aq", "--filter", f"name=^{name}$"]]
    assert len(checks) == shell.CLEANUP_CHECKS
    docker.running.clear()

def test_cancellation_while_launching_still_removes_the_container(docker, registry, settings):
    """Annulée pendant create_subprocess_exec, l'attente laisse un conteneur déjà démarré : il est retiré."""
    function = handler()
    docker.gate["launch"] = asyncio.Event()

    async def body():
        call = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        for _ in range(200):
            if not docker.running and all(w.active == 0 for w in registry.live()):
                break
            await asyncio.sleep(0.01)
        return dict(docker.running), [w.active for w in registry.live()]
    running, active = scenario(registry, body)
    assert running == {} and active == [0]
    assert any(c[0] == "kill" for c in docker.commands)


def test_failed_cleanup_retires_the_workspace_and_keeps_it_counted(docker, registry, settings, monkeypatch, clock):
    """La commande annulée tourne peut-être encore : la session ne remonte jamais ce /tmp."""
    monkeypatch.setattr(shell, "CLEANUP_CHECK_INTERVAL", 0)
    settings["value"] = make_settings(shell_workspace_max_count=2)
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        docker.fail.update({"kill", "rm"})
        call = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        old = mounted_volume(docker.calls[0])
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        for _ in range(300):
            if registry._doomed:
                break
            await asyncio.sleep(0.01)
        docker.gate.pop("call")
        again = await invoke(function, "ls")
        counted = len(registry.live())
        docker.fail.clear()
        await registry.sweep(settings["value"])
        await registry.stop()
        return old, again, counted
    old, again, counted = scenario(registry, body)
    assert again["workspace"]["new"] is True
    assert mounted_volume(docker.calls[-1]) != old
    assert counted == 2
    assert old not in docker.volumes and docker.running == {}
    assert len(registry.live()) == 1


def test_workspace_retired_during_the_holder_check_is_not_handed_out(docker, registry, settings, monkeypatch):
    """release(orphaned=True) tourne hors du verrou : il peut retirer l'espace pendant le contrôle du maintien."""
    function = handler()
    real_check = registry._holder_running

    async def body():
        await invoke(function)
        old = registry.live()[0]

        async def check_while_retiring(workspace):
            running = await real_check(workspace)
            old.active += 1
            registry.release(shell_workspace.Lease(old), orphaned=True)
            return running
        monkeypatch.setattr(registry, "_holder_running", check_while_retiring)
        result = await invoke(function)
        await registry.stop()
        return old, result
    old, result = scenario(registry, body)
    assert result["workspace"]["new"] is True and result["workspace"]["reason"] == "orphaned"
    assert mounted_volume(docker.calls[-1]) != old.volume
    assert old.volume not in docker.volumes and old.active == 0
    assert len(registry.live()) == 1

def test_background_purge_retries_without_waiting_for_a_call(docker, registry, settings, monkeypatch):
    monkeypatch.setattr(shell_workspace, "SWEEP_INTERVAL_SECONDS", 0.01)
    settings["value"] = make_settings(shell_workspace_max_count=0)
    docker.leftover_containers = ["old-holder"]
    docker.fail.add("ps")
    function = handler()

    async def body():
        await invoke(function, "ls")
        await asyncio.sleep(0.05)
        failed_once = docker.leftover_containers == ["old-holder"]
        docker.fail.clear()
        for _ in range(200):
            if docker.leftover_containers == []:
                break
            await asyncio.sleep(0.01)
        return failed_once
    failed_once = scenario(registry, body)
    assert failed_once and docker.leftover_containers == []
    assert len(docker.calls) == 1


def test_xattr_guard_covers_every_setxattr_entry_point():
    """Numéros d'appel système : x86_64 et aarch64 (asm-generic), setxattrat commun depuis Linux 6.13."""
    namespace = {}
    source = shell_workspace.XATTR_GUARD.split("if platform.machine() not in ARCHES")[0]
    exec(source, namespace)
    assert namespace["ARCHES"] == {"x86_64": (0xC000003E, (188, 189, 190)), "aarch64": (0xC00000B7, (5, 6, 7))}
    assert "numbers = numbers + (463,)" in shell_workspace.XATTR_GUARD



def _guard_program(machine):
    """Programme BPF que XATTR_GUARD construit sur `machine`, sans l'installer."""
    source = shell_workspace.XATTR_GUARD.split("program = ")[0].replace("platform.machine()", repr(machine))
    namespace = {}
    exec(source, namespace)
    return namespace["code"]


def _run_bpf(code, nr, arch):
    """Interprète les seules instructions du filtre : LD W ABS, JEQ K, JGE K, RET K, sur seccomp_data."""
    data = {0: nr, 4: arch}
    accumulator, pc = 0, 0
    while True:
        op, jt, jf, k = code[pc]
        if op == 0x20:
            accumulator, pc = data[k], pc + 1
        elif op in (0x15, 0x35):
            taken = accumulator == k if op == 0x15 else accumulator >= k
            pc += 1 + (jt if taken else jf)
        elif op == 0x06:
            return k
        else:
            raise AssertionError(f"instruction inattendue {op:#x}")
        assert pc < len(code)


@pytest.mark.parametrize("machine, arch, xattr, ordinary", [
    ("x86_64", 0xC000003E, (188, 189, 190, 463), (0, 1, 2, 257, 59, 231)),
    ("aarch64", 0xC00000B7, (5, 6, 7, 463), (63, 64, 56, 221, 93, 8)),
])
def test_xattr_guard_program_decisions(machine, arch, xattr, ordinary):
    deny, allow = 0x00050000 | 95, 0x7FFF0000
    code = _guard_program(machine)
    for nr in xattr:
        assert _run_bpf(code, nr, arch) == deny
    for nr in ordinary:
        assert _run_bpf(code, nr, arch) == allow
    # Appel x32 (bit 30) et architecture inattendue : refusés quel que soit le numéro.
    assert _run_bpf(code, 0x40000000 | 1, arch) == deny
    for other in (0x40000003, 0xC000003E if machine == "aarch64" else 0xC00000B7):
        assert _run_bpf(code, ordinary[0], other) == deny
        assert _run_bpf(code, xattr[0], other) == deny

def test_workspace_call_runs_under_the_xattr_guard(docker, registry, settings):
    scenario(registry, lambda: invoke(handler(), "ls /tmp"))
    call = docker.calls[0]
    image = call.index(settings["value"].sandbox_image)
    assert call[image + 1:] == ["python3", "-I", "-S", "-c", shell_workspace.XATTR_GUARD, "bash", "-c", "ls /tmp"]
    compile(shell_workspace.XATTR_GUARD, "xattr_guard", "exec")

def test_workspace_is_not_handed_out_while_a_call_container_is_being_removed(docker, registry, settings):
    """A annulé, son conteneur pas encore retiré : B de la même session ne remonte pas ce /tmp."""
    function = handler()
    docker.gate["call"] = asyncio.Event()
    docker.gate["kill"] = asyncio.Event()

    async def body():
        call = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        volume = mounted_volume(docker.calls[0])
        docker.gate.pop("call")
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        during = await invoke(function)
        docker.gate.pop("kill").set()
        for _ in range(200):
            if all(w.active == 0 and w.cleaning == 0 for w in registry.live()):
                break
            await asyncio.sleep(0.01)
        after = await invoke(function)
        return volume, during, after
    volume, during, after = scenario(registry, body)
    assert during["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert mounted_volume(docker.calls[1]) is None
    assert after["workspace"]["persistent"] is True and mounted_volume(docker.calls[2]) == volume


def test_timeout_with_failed_cleanup_does_not_promise_the_workspace(docker, registry, settings, monkeypatch):
    monkeypatch.setattr(shell, "CLEANUP_CHECK_INTERVAL", 0)
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        docker.fail.update({"kill", "rm"})
        result = await invoke(function, "sleep 600", timeout=1)
        for _ in range(200):
            if registry._doomed:
                break
            await asyncio.sleep(0.01)
        docker.fail.clear()
        docker.gate.pop("call").set()
        return result
    result = scenario(registry, body)
    assert result["status"] == "error" and result["message"].startswith("Timeout")
    assert result["workspace"] == {"persistent": False, "reason": "orphaned"}
    assert "non confirmé" in result["hint"]


def test_unremoved_ephemeral_container_is_retried_until_removed(docker, registry, settings, monkeypatch):
    """Sans espace, aucun registre ne reprend le retrait : la tâche de reprise le fait."""
    monkeypatch.setattr(shell, "CLEANUP_CHECK_INTERVAL", 0)
    monkeypatch.setattr(shell, "CLEANUP_RETRY_INTERVAL", 0.01)
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        docker.fail.update({"kill", "rm"})
        call = asyncio.ensure_future(invoke(function, "sleep 600", sid=None))
        while not docker.running:
            await asyncio.sleep(0)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        for _ in range(300):
            if shell._UNREMOVED:
                break
            await asyncio.sleep(0.01)
        still = dict(docker.running)
        docker.fail.clear()
        for _ in range(300):
            if not shell._UNREMOVED and not docker.running:
                break
            await asyncio.sleep(0.01)
        docker.gate.pop("call").set()
        return still
    still = scenario(registry, body)
    assert len(still) == 1
    assert docker.running == {} and shell._UNREMOVED == set()
    assert mounted_volume(docker.calls[0]) is None


def test_purge_restarts_after_stop_before_its_first_step(docker, registry, settings):
    async def body():
        registry.prepare(settings["value"])
        await registry.stop()
        registry.prepare(settings["value"])
        for _ in range(200):
            if registry._purged:
                break
            await asyncio.sleep(0.01)
        return registry._purged
    assert scenario(registry, body) is True

async def _settle(docker, registry):
    for _ in range(300):
        if not docker.running and all(w.active == 0 and w.cleaning == 0 for w in registry.live()):
            return
        await asyncio.sleep(0.01)


def test_call_does_not_promise_a_workspace_retired_while_it_ran(docker, registry, settings, monkeypatch):
    """B, même session, échoue à retirer son conteneur pendant que A tourne : A n'annonce plus l'espace."""
    real_run = shell._run_in_sandbox

    async def run_then_other_call_fails(*args, **kwargs):
        result = await real_run(*args, **kwargs)
        other = registry.live()[0]
        other.active += 1
        registry.release(shell_workspace.Lease(other), orphaned=True)
        return result
    monkeypatch.setattr(shell, "_run_in_sandbox", run_then_other_call_fails)

    async def body():
        result = await invoke(handler())
        await registry.stop()
        return result
    result = scenario(registry, body)
    assert result["status"] == "success"
    assert result["workspace"] == {"persistent": False, "reason": "orphaned"}
    assert "n'est plus conservé" in result["hint"]


def test_client_exit_with_container_still_running_triggers_cleanup(docker, registry, settings):
    """Client docker run terminé, conteneur encore en marche : l'espace n'est rendu qu'après son retrait."""
    function = handler()
    docker.leave_running = True

    async def body():
        first = await invoke(function)
        docker.leave_running = False
        await _settle(docker, registry)
        second = await invoke(function)
        return first, second
    first, second = scenario(registry, body)
    assert first["status"] == "success"
    assert first["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    name = option(docker.calls[0], "--name=")
    assert ["kill", name] in docker.commands and docker.running == {}
    assert second["workspace"]["persistent"] is True and second["workspace"]["new"] is False
    assert mounted_volume(docker.calls[1]) == mounted_volume(docker.calls[0])


def test_client_failure_during_the_call_triggers_cleanup(docker, registry, settings):
    function = handler()
    docker.client_error = True

    async def body():
        first = await invoke(function)
        docker.client_error = False
        await _settle(docker, registry)
        return first
    first = scenario(registry, body)
    assert first["status"] == "error" and "connexion" in first["message"]
    assert first["workspace"]["persistent"] is False
    assert first["workspace"]["reason"] in ("cleanup_pending", "orphaned")
    name = option(docker.calls[0], "--name=")
    assert ["kill", name] in docker.commands and docker.running == {}
    assert [w.active for w in registry.live()] == [0]

def test_cancellation_during_the_post_call_check_keeps_the_reservation(docker, registry, settings):
    """Annulé pendant le docker ps de fin d'appel : le conteneur peut tourner, l'espace reste réservé."""
    function = handler()

    async def body():
        await invoke(function)
        docker.leave_running = True
        docker.gate["ps"] = asyncio.Event()
        call = asyncio.ensure_future(invoke(function))
        # Le premier appel a déjà fait son contrôle : attendre celui du second.
        while sum(1 for c in docker.commands if c[0] == "ps" and "status=running" in c) < 2:
            await asyncio.sleep(0)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        await asyncio.sleep(0.01)
        during = [(w.active, w.cleaning) for w in registry.live()]
        docker.leave_running = False
        docker.gate.pop("ps").set()
        await _settle(docker, registry)
        return during
    during = scenario(registry, body)
    assert during == [(1, 1)]
    name = option(docker.calls[1], "--name=")
    assert ["kill", name] in docker.commands and docker.running == {}
    assert [w.active for w in registry.live()] == [0]


def test_call_reports_a_concurrent_cleanup_of_its_session(docker, registry, settings):
    """A et B partagent l'espace ; B est annulé, son retrait traîne : A n'annonce pas l'espace."""
    function = handler()
    docker.gate["call"] = asyncio.Event()
    docker.gate["kill"] = asyncio.Event()

    async def body():
        first = asyncio.ensure_future(invoke(function, "sleep 1"))
        second = asyncio.ensure_future(invoke(function, "sleep 600"))
        while len(docker.running) < 2:
            await asyncio.sleep(0)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        docker.gate.pop("call").set()
        result = await first
        docker.gate.pop("kill").set()
        await _settle(docker, registry)
        return result
    result = scenario(registry, body)
    assert result["status"] == "success"
    assert result["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    assert "détruit à la fin de l'appel" not in result["hint"]


def test_call_finishing_after_max_age_does_not_promise_the_workspace(docker, registry, settings, clock, monkeypatch):
    settings["value"] = make_settings(shell_workspace_idle_seconds=100_000)
    max_age = settings["value"].shell_workspace_max_age_seconds
    real_run = shell._run_in_sandbox

    async def run_past_max_age(*args, **kwargs):
        result = await real_run(*args, **kwargs)
        clock.now += max_age
        return result
    monkeypatch.setattr(shell, "_run_in_sandbox", run_past_max_age)
    result = scenario(registry, lambda: invoke(handler()))
    assert result["workspace"] == {"persistent": False, "reason": "expired"}
    assert "n'est plus conservé" in result["hint"] and "a été retiré" not in result["hint"]


def test_hints_never_promise_what_the_server_has_not_established(docker, registry, settings, monkeypatch):
    retired = shell._ephemeral_hint("orphaned")
    assert "indiquera un espace neuf" not in retired
    # Cet appel a déjà son champ workspace, sans espace : seul l'appel suivant peut en recevoir un.
    assert "le champ workspace de l'appel suivant dira s'il reçoit un espace neuf" in retired
    assert "de cet appel dira" not in retired
    pending = shell._ephemeral_hint("cleanup_pending")
    assert "détruit à la fin de l'appel" not in pending and "pas encore confirmé" in pending
    docker.fail.add("volume create")

    async def missing(*args, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(shell, "_run_in_sandbox", missing)
    result = scenario(registry, lambda: invoke(handler(), cwd="/tmp/a"))
    assert "a démarré" not in result["hint"]
    assert result["workspace"] == {"persistent": False, "reason": "unavailable"}


def test_startup_purge_on_the_first_call_does_not_carry_its_trace(docker, registry, settings, monkeypatch):
    from src.mcp_tools import observability
    docker.leftover_containers = ["old-holder"]
    seen = []
    monkeypatch.setattr(shell_workspace, "record_activity",
                        lambda event, **kw: seen.append((event, dict(observability._activity_context.get()))))

    async def body():
        observability._activity_context.set({"actor": "caller-A", "trace_id": "trace-A"})
        return await invoke(handler())
    result = scenario(registry, body)
    assert result["workspace"]["persistent"] is True
    purged = [context for event, context in seen if event == "shell.workspace.purged"]
    created = [context for event, context in seen if event == "shell.workspace.created"]
    assert purged == [{}]
    assert created and created[0].get("trace_id") == "trace-A"

def test_holder_lost_during_the_call_is_reported(docker, registry, settings, monkeypatch):
    """Le maintien s'arrête pendant l'appel : ses fichiers disparaissent avec le conteneur d'appel."""
    real_run = shell._run_in_sandbox
    function = handler()

    async def run_while_holder_stops(*args, **kwargs):
        docker.holders.clear()
        return await real_run(*args, **kwargs)

    async def body():
        await invoke(function)
        old = registry.live()[0].volume
        monkeypatch.setattr(shell, "_run_in_sandbox", run_while_holder_stops)
        during = await invoke(function)
        monkeypatch.setattr(shell, "_run_in_sandbox", real_run)
        after = await invoke(function)
        return old, during, after
    old, during, after = scenario(registry, body)
    assert during["status"] == "success"
    assert during["workspace"] == {"persistent": False, "reason": "lost"}
    assert after["workspace"]["new"] is True and after["workspace"]["reason"] == "lost"
    assert mounted_volume(docker.calls[-1]) != old


def test_uncertain_end_check_does_not_declare_the_holder_lost(docker, registry, settings):
    """Inventaire de fin d'appel en échec : rien ne prouve la perte du maintien ; le conteneur d'appel est retiré."""
    function = handler()
    docker.gate["kill"] = asyncio.Event()

    async def body():
        await invoke(function)
        workspace = registry.live()[0]
        docker.fail.add("ps")
        during = await invoke(function)
        lost = workspace.holder_lost
        docker.fail.discard("ps")
        docker.gate.pop("kill").set()
        await _settle(docker, registry)
        return during, lost
    during, lost = scenario(registry, body)
    assert lost is False
    assert during["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    assert any(c[0] == "kill" for c in docker.commands)

def test_timeout_with_confirmed_cleanup_keeps_announcing_the_workspace(docker, registry, settings):
    """Délai dépassé, retrait confirmé avant la réponse : les fichiers restent, l'espace est annoncé."""
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        await asyncio.sleep(0)
        result = await invoke(function, "sleep 600", timeout=1)
        docker.gate.pop("call").set()
        await _settle(docker, registry)
        after = await invoke(function)
        return result, after
    result, after = scenario(registry, body)
    assert result["message"].startswith("Timeout")
    assert result["workspace"]["persistent"] is True
    assert after["workspace"]["persistent"] is True and after["workspace"]["new"] is False
    assert mounted_volume(docker.calls[0]) == mounted_volume(docker.calls[1])

def test_timeout_response_does_not_wait_for_a_slow_cleanup(docker, registry, settings, monkeypatch):
    monkeypatch.setattr(shell, "CLEANUP_RESPONSE_WAIT", 0.05)
    function = handler()
    docker.gate["call"] = asyncio.Event()
    docker.gate["kill"] = asyncio.Event()

    async def body():
        loop = asyncio.get_running_loop()
        start = loop.time()
        try:
            # Borne du test : une réponse qui attendrait tout le nettoyage échoue ici, sans bloquer.
            result = await asyncio.wait_for(invoke(function, "sleep 600", timeout=1), 5)
        except asyncio.TimeoutError:
            result = None
        elapsed = loop.time() - start
        reserved = [w.active for w in registry.live()]
        docker.gate.pop("kill").set()
        await _settle(docker, registry)
        docker.gate.pop("call").set()
        return result, elapsed, reserved
    result, elapsed, reserved = scenario(registry, body)
    assert result is not None and elapsed < 3
    assert result["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    assert reserved == [1]
    assert registry.live()[0].active == 0 and docker.running == {}


def test_timeout_after_holder_loss_does_not_announce_the_workspace(docker, registry, settings):
    """Délai dépassé, maintien arrêté pendant l'appel, retrait confirmé : les fichiers ont disparu."""
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        call = asyncio.ensure_future(invoke(function, "sleep 600", timeout=1))
        while not docker.running:
            await asyncio.sleep(0)
        old = registry.live()[0].volume
        docker.holders.clear()
        result = await call
        docker.gate.pop("call").set()
        await _settle(docker, registry)
        after = await invoke(function)
        return old, result, after
    old, result, after = scenario(registry, body)
    assert result["message"].startswith("Timeout")
    assert result["workspace"] == {"persistent": False, "reason": "lost"}
    assert after["workspace"]["new"] is True and after["workspace"]["reason"] == "lost"
    assert mounted_volume(docker.calls[-1]) != old


def test_timeout_with_uncertain_inventory_does_not_announce_the_workspace(docker, registry, settings, monkeypatch):
    """Retrait confirmé, inventaire du maintien en échec : rien ne prouve que les fichiers restent."""
    function = handler()
    real_inventory = shell._end_inventory
    failing = {"on": True}

    async def inventory(container_name, workspace):
        if failing["on"]:
            return -1, []
        return await real_inventory(container_name, workspace)
    monkeypatch.setattr(shell, "_end_inventory", inventory)
    docker.gate["call"] = asyncio.Event()

    async def body():
        result = await invoke(function, "sleep 600", timeout=1)
        lost = registry.live()[0].holder_lost
        failing["on"] = False
        docker.gate.pop("call").set()
        await _settle(docker, registry)
        after = await invoke(function)
        return result, lost, after
    result, lost, after = scenario(registry, body)
    assert result["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    assert lost is False
    assert after["workspace"]["persistent"] is True and after["workspace"]["new"] is False
    assert mounted_volume(docker.calls[0]) == mounted_volume(docker.calls[1])


def test_timeout_inventory_stays_within_the_response_wait(docker, registry, settings, monkeypatch):
    """L'inventaire du maintien partage la borne de CLEANUP_RESPONSE_WAIT avec le retrait.

    Le retrait consomme 0,6 s du délai de 1 s : l'inventaire bloqué n'en reçoit que
    le reste. Un délai rendu entier à l'inventaire porterait la réponse à 1,6 s.
    """
    monkeypatch.setattr(shell, "CLEANUP_RESPONSE_WAIT", 1.0)
    function = handler()
    stuck = asyncio.Event()
    times = {}
    real_kill = shell._kill_container

    async def slow_kill(name):
        times["cleanup"] = asyncio.get_running_loop().time()
        await asyncio.sleep(0.6)
        return await real_kill(name)
    monkeypatch.setattr(shell, "_kill_container", slow_kill)

    async def slow_inventory(container_name, workspace):
        times["inventory"] = asyncio.get_running_loop().time()
        await stuck.wait()
        return 0, [workspace.holder]
    monkeypatch.setattr(shell, "_end_inventory", slow_inventory)
    docker.gate["call"] = asyncio.Event()

    async def body():
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(invoke(function, "sleep 600", timeout=1), 5)
        except asyncio.TimeoutError:
            result = None
        times["answer"] = loop.time()
        stuck.set()
        docker.gate.pop("call").set()
        await _settle(docker, registry)
        return result
    result = scenario(registry, body)
    assert result is not None and "inventory" in times
    assert times["inventory"] - times["cleanup"] >= 0.6
    assert times["answer"] - times["cleanup"] < 1.3
    assert result["workspace"] == {"persistent": False, "reason": "cleanup_pending"}


def test_paused_holder_is_not_declared_lost(docker, registry, settings):
    """Un maintien en pause monte encore le volume : ni perte annoncée, ni espace remplacé."""
    function = handler()

    async def body():
        await invoke(function)
        workspace = registry.live()[0]
        docker.paused.add(workspace.holder)
        during = await invoke(function)
        lost = workspace.holder_lost
        docker.paused.clear()
        after = await invoke(function)
        return during, lost, after
    during, lost, after = scenario(registry, body)
    assert lost is False
    assert during["workspace"]["persistent"] is True and during["workspace"]["new"] is False
    assert after["workspace"]["persistent"] is True and after["workspace"]["new"] is False
    assert len({mounted_volume(c) for c in docker.calls}) == 1


def test_paused_call_container_is_still_removed(docker, registry, settings):
    """Un conteneur d'appel en pause monte encore l'espace : il est retiré avant de rendre la réservation."""
    function = handler()

    async def body():
        await invoke(function)
        docker.leave_running = True
        docker.pause_calls = True
        docker.gate["kill"] = asyncio.Event()
        result = await invoke(function)
        held = [(w.active, w.cleaning) for w in registry.live()]
        docker.leave_running = docker.pause_calls = False
        docker.gate.pop("kill").set()
        await _settle(docker, registry)
        return result, held
    result, held = scenario(registry, body)
    assert result["workspace"] == {"persistent": False, "reason": "cleanup_pending"}
    assert held == [(1, 1)]
    name = option(docker.calls[1], "--name=")
    assert ["kill", name] in docker.commands and docker.running == {}


def test_end_check_seeing_only_the_call_container_holds_the_reservation(docker, registry, settings, monkeypatch):
    """Maintien arrêté, conteneur d'appel encore en marche : perte annoncée, retrait avant la remise."""
    function = handler()
    real_run = shell._run_in_sandbox

    async def run_while_holder_stops(*args, **kwargs):
        docker.holders.clear()
        return await real_run(*args, **kwargs)

    async def body():
        await invoke(function)
        docker.leave_running = True
        docker.gate["kill"] = asyncio.Event()
        monkeypatch.setattr(shell, "_run_in_sandbox", run_while_holder_stops)
        result = await invoke(function)
        held = [(w.active, w.cleaning) for w in registry.live()]
        docker.leave_running = False
        docker.gate.pop("kill").set()
        await _settle(docker, registry)
        return result, held
    result, held = scenario(registry, body)
    assert result["workspace"] == {"persistent": False, "reason": "lost"}
    assert held == [(1, 1)]
    name = option(docker.calls[1], "--name=")
    assert ["kill", name] in docker.commands and docker.running == {}


@pytest.mark.parametrize("max_count", [16, 1])
def test_admission_does_not_hand_out_a_workspace_lost_during_its_holder_check(docker, registry, settings,
                                                                              monkeypatch, max_count):
    """L'inspect de B voit le maintien en marche ; A confirme sa perte avant que B ne reprenne la main."""
    settings["value"] = make_settings(shell_workspace_max_count=max_count)
    function = handler()

    async def body():
        await invoke(function)
        old = registry.live()[0].volume
        docker.gate["call"] = asyncio.Event()
        first = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        real_check = registry._holder_running
        read, resume = asyncio.Event(), asyncio.Event()

        async def stale_check(workspace):
            running = await real_check(workspace)
            read.set()
            await resume.wait()
            return running
        monkeypatch.setattr(registry, "_holder_running", stale_check)
        second = asyncio.ensure_future(invoke(function, "echo B"))
        await read.wait()
        docker.holders.clear()
        docker.gate.pop("call").set()
        a = await first
        resume.set()
        b = await second
        return old, a, b
    old, a, b = scenario(registry, body)
    assert a["workspace"] == {"persistent": False, "reason": "lost"}
    assert all(mounted_volume(c) == old for c in docker.calls[:2])
    if max_count == 1:
        assert b["status"] == "error" and b["message"] == shell.CAPACITY_MESSAGE
        assert len(docker.calls) == 2
    else:
        assert b["workspace"]["new"] is True and b["workspace"]["reason"] == "lost"
        assert len(docker.calls) == 3 and mounted_volume(docker.calls[2]) != old


def test_inspect_with_unexpected_output_keeps_the_workspace(docker, registry, settings):
    function = handler()

    async def body():
        await invoke(function)
        volume = registry.live()[0].volume
        docker.inspect_output = b""
        docker.fail.add("ps")
        during = await invoke(function)
        return volume, during
    volume, during = scenario(registry, body)
    assert during["workspace"] == {"persistent": False, "reason": "unavailable"}
    assert volume in docker.volumes and not any(c[:2] == ["volume", "rm"] for c in docker.commands)


def test_missing_docker_cli_keeps_the_workspace_state(docker, registry, settings, monkeypatch):
    docker.fail.add("volume create")

    async def missing(*args, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(shell, "_run_in_sandbox", missing)
    result = scenario(registry, lambda: invoke(handler()))
    assert result["message"].startswith("Docker CLI non trouvé")
    assert result["workspace"] == {"persistent": False, "reason": "unavailable"}
    # Sans session, la réponse reste celle de main.
    plain = scenario(registry, lambda: invoke(handler(), sid=None))
    assert set(plain) == {"status", "message"}


def test_background_retry_does_not_carry_the_trace_of_the_call(docker, registry, settings, monkeypatch):
    from src.mcp_tools import observability
    monkeypatch.setattr(shell, "CLEANUP_CHECK_INTERVAL", 0)
    monkeypatch.setattr(shell, "CLEANUP_RETRY_INTERVAL", 0.01)
    seen = []
    monkeypatch.setattr(shell, "record_activity",
                        lambda event, **kw: seen.append((event, dict(observability._activity_context.get()))))
    function = handler()
    docker.gate["call"] = asyncio.Event()

    async def body():
        observability._activity_context.set({"actor": "caller-A", "trace_id": "trace-A"})
        docker.fail.update({"kill", "rm"})
        call = asyncio.ensure_future(invoke(function, "sleep 600", sid=None))
        while not docker.running:
            await asyncio.sleep(0)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        for _ in range(300):
            if shell._UNREMOVED:
                break
            await asyncio.sleep(0.01)
        docker.fail.clear()
        for _ in range(300):
            if not shell._UNREMOVED:
                break
            await asyncio.sleep(0.01)
        docker.gate.pop("call").set()
    scenario(registry, body)
    recovered = [context for event, context in seen if event == "sandbox.cleanup_recovered"]
    failed = [context for event, context in seen if event == "sandbox.cleanup_failed"]
    assert recovered == [{}]
    # Le nettoyage de l'appel, lui, garde sa trace.
    assert failed and failed[0].get("trace_id") == "trace-A"

def test_workspace_stays_reserved_until_the_call_container_is_gone(docker, registry, settings, clock):
    function = handler()
    docker.gate["call"] = asyncio.Event()
    docker.gate["kill"] = asyncio.Event()

    async def body():
        call = asyncio.ensure_future(invoke(function, "sleep 600"))
        while not docker.running:
            await asyncio.sleep(0)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        clock.now += 10_000
        await registry.sweep(settings["value"])
        during = ([w.active for w in registry.live()], len(docker.volumes))
        docker.gate.pop("kill").set()
        for _ in range(200):
            if registry.live() == []:
                break
            await registry.sweep(settings["value"])
            await asyncio.sleep(0.01)
        return during
    during = scenario(registry, body)
    assert during == ([1], 1)
    assert registry.live() == [] and docker.volumes == {} and docker.running == {}


def test_removal_also_stops_an_orphan_call_container(docker, registry, settings, clock):
    function = handler()

    async def body():
        await invoke(function)
        volume = registry.live()[0].volume
        docker.running["sandbox-orphan"] = volume
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return volume
    volume = scenario(registry, body)
    assert ["ps", "-aq", "--filter", f"volume={volume}"] in docker.commands
    assert ["rm", "-f", "sandbox-orphan"] in docker.commands
    assert registry.live() == [] and docker.volumes == {} and docker.running == {}


def test_startup_purge_runs_even_when_workspaces_are_disabled(docker, registry, settings):
    """Après un retour à 0, les anciens maintiens ne gardent pas leur tmpfs jusqu'à leur échéance."""
    settings["value"] = make_settings(shell_workspace_max_count=0)
    docker.leftover_containers = ["old-holder"]
    docker.leftover_volumes = ["shellws-old"]
    function = handler()

    async def body():
        result = await invoke(function, "ls")
        await registry.stop()
        return result
    result = scenario(registry, body)
    assert "workspace" not in result
    assert ["rm", "-f", "old-holder"] in docker.commands and ["volume", "rm", "shellws-old"] in docker.commands
    assert docker.leftover_containers == [] and docker.leftover_volumes == []
    assert mounted_volume(docker.calls[0]) is None


def test_missing_path_hint_names_the_session_workspace(docker, registry, settings, monkeypatch):
    async def failing(*args, **kwargs):
        return {"status": "error", "stdout": "", "stderr": "cd: /tmp/src: No such file or directory\n",
                "returncode": 1, "sandbox": True}
    monkeypatch.setattr(shell, "_run_in_sandbox", failing)
    function = handler()

    async def body():
        return await invoke(function, "cd /tmp/src"), await invoke(function, "cd /tmp/src")
    first, second = scenario(registry, body)
    assert first["hint"] == shell.NEW_WORKSPACE_HINT
    assert second["hint"] == shell.WORKSPACE_HINT


def test_startup_purge_only_targets_this_instance(docker, registry, settings):
    docker.leftover_containers = ["old-holder", "old-call"]
    docker.leftover_volumes = ["shellws-old"]
    scenario(registry, lambda: invoke(handler()))
    ps = next(c for c in docker.commands if c[0] == "ps")
    ls = next(c for c in docker.commands if c[:2] == ["volume", "ls"])
    instance = f"label={shell_workspace.INSTANCE_LABEL}=t72"
    assert instance in ps and f"label={shell_workspace.LABEL}" in ps
    assert instance in ls and f"label={shell_workspace.LABEL}={shell_workspace.VOLUME_ROLE}" in ls
    assert ["rm", "-f", "old-holder", "old-call"] in docker.commands
    assert ["volume", "rm", "shellws-old"] in docker.commands
    # Inventaire, puis second inventaire qui confirme la purge ; aucun autre au deuxième appel.
    assert sum(1 for c in docker.commands if c[0] == "ps" and instance in c) == 2
    # Seul autre ps : le contrôle du conteneur d'appel après la fin de son client.
    holder = next(iter(docker.holders))
    assert [c for c in docker.commands if c[0] == "ps" and instance not in c] == [
        ["ps", "--format", "{{.Names}}", "--filter", f"name=^{shell_workspace_call_name(docker)}$",
         "--filter", f"name=^{holder}$", "--filter", "status=running", "--filter", "status=paused"]]
    assert docker.leftover_containers == [] and docker.leftover_volumes == []


# --- journaux -----------------------------------------------------------------------

def test_activity_never_carries_the_session_id_or_token(docker, registry, settings, monkeypatch, clock):
    events = []
    monkeypatch.setattr(shell_workspace, "record_activity", lambda *a, **k: events.append((a, k)))
    function = handler()

    async def body():
        await invoke(function)
        clock.now += 10_000
        await registry.sweep(settings["value"])
    scenario(registry, body)
    text = json.dumps(events, default=str)
    assert {e[0][0] for e in events} >= {"shell.workspace.created", "shell.workspace.removed"}
    for secret in (SID_A, sha("token-A"), "token-A", registry_key()):
        assert secret not in text
    assert registry_key()[:8] in text


def registry_key():
    return shell_workspace.workspace_key(SID_A, sha("token-A"))


def test_sdk_session_logs_are_redacted():
    records = []

    class Keep(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))
    for name in shell_workspace.SDK_SESSION_LOGGERS:
        logger = logging.getLogger(name)
        handler_ = Keep()
        logger.addHandler(handler_)
        logger.setLevel(logging.INFO)
        try:
            logger.info(f"Created new transport with session ID: {SID_A}")
            logger.info("Session %s idle timeout", SID_A)
        finally:
            logger.removeHandler(handler_)
            logger.setLevel(logging.NOTSET)
    assert len(records) == 4
    assert all(SID_A not in r and "session:" + sha(SID_A)[:8] in r for r in records)


def test_waf_access_log_drops_the_session_header():
    caddyfile = (Path(__file__).parent.parent / "waf" / "Caddyfile").read_text()
    assert "request>headers>Mcp-Session-Id delete" in caddyfile
    assert "resp_headers>Mcp-Session-Id delete" in caddyfile


# --- transport HTTP réel ---------------------------------------------------------------

class HttpHarness:
    """uvicorn + vrai AuthMiddleware + streamable HTTP du SDK 2.2 + vrai outil shell."""

    def __init__(self, port):
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.client = httpx.AsyncClient(timeout=60)

    async def post(self, body, *, token="token-A", sid=None, version="2025-06-18", headers=None):
        merged = [("accept", "application/json, text/event-stream"), ("content-type", "application/json"),
                  ("mcp-protocol-version", version)]
        if token is not None:
            merged.append(("authorization", f"Bearer {token}"))
        if sid is not None:
            merged.append(("mcp-session-id", sid))
        merged += headers or []
        return await self.client.post(self.url, headers=merged, content=json.dumps(body))

    async def open(self, token):
        reply = await self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
            token=token)
        sid = reply.headers["mcp-session-id"]
        await self.post({"jsonrpc": "2.0", "method": "notifications/initialized"}, token=token, sid=sid)
        return sid

    async def shell(self, command, *, token="token-A", sid=None, meta=None, extra=None, **kwargs):
        params = {"name": "shell", "arguments": {"command": command, **(extra or {})}}
        if meta is not None:
            params["_meta"] = meta
        reply = await self.post({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params},
                                token=token, sid=sid, **kwargs)
        if reply.status_code != 200:
            return reply.status_code, None
        data = next(line[6:] for line in reply.text.splitlines() if line.startswith("data: ")) \
            if reply.text.startswith("event:") else reply.text
        return 200, json.loads(json.loads(data)["result"]["content"][0]["text"])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_http(registry, monkeypatch, body):
    # sse_starlette garde, par fil, un indicateur d'arrêt qu'un serveur précédent du
    # même processus de test a pu lever : il fermerait d'emblée les flux SSE suivants.
    import sse_starlette.sse as sse
    monkeypatch.setattr(sse.AppStatus, "should_exit", False)
    monkeypatch.setattr(sse._thread_state, "shutdown_state", None, raising=False)
    monkeypatch.setattr(auth_middleware.AuthMiddleware, "_validate_token",
                        lambda self, token: dict(TOKENS[token]) if token in TOKENS else None)
    server = MCPServer("shell-workspace-72")
    shell.register(server)
    app = auth_middleware.AuthMiddleware(server.streamable_http_app(host="127.0.0.1"))

    async def main():
        port = free_port()
        uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on"))
        task = asyncio.ensure_future(uv.serve())
        while not uv.started:
            await asyncio.sleep(0.02)
        harness = HttpHarness(port)
        try:
            return await body(harness)
        finally:
            await harness.client.aclose()
            await registry.stop()
            uv.should_exit = True
            await task
    return asyncio.run(main())


def test_http_same_session_shares_other_session_does_not(docker, registry, settings, monkeypatch):
    async def body(h):
        sid_a = await h.open("token-A")
        sid_a2 = await h.open("token-A")
        replies = [await h.shell("echo 1", sid=sid_a), await h.shell("echo 2", sid=sid_a),
                   await h.shell("echo 3", sid=sid_a2)]
        return sid_a, replies
    sid_a, replies = run_http(registry, monkeypatch, body)
    assert [status for status, _ in replies] == [200, 200, 200]
    first, second, other_session = [mounted_volume(c) for c in docker.calls]
    assert first == second != other_session
    assert [r["workspace"]["new"] for _, r in replies] == [True, False, True]
    for _, reply in replies:
        assert sid_a not in json.dumps(reply)


def test_http_session_is_bound_to_the_token_that_opened_it(docker, registry, settings, monkeypatch):
    """Un autre jeton qui présente l'identifiant reçoit 404 du SDK, avant tout routage vers le transport.

    Sans cette liaison, les deux jetons partageaient le transport de la session,
    donc sa table de réponses indexée par identifiant JSON-RPC.
    """
    async def body(h):
        sid_a = await h.open("token-A")
        await h.shell("echo a", sid=sid_a)
        before = len(docker.commands)
        intruder = [await h.shell("cat /tmp/f", token="token-B", sid=sid_a),
                    await h.post({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}, token="token-B", sid=sid_a)]
        after = len(docker.commands)
        owner = await h.shell("echo a2", sid=sid_a)
        return intruder, before, after, owner
    intruder, before, after, owner = run_http(registry, monkeypatch, body)
    assert intruder[0] == (404, None)
    assert intruder[1].status_code == 404
    assert before == after
    assert owner[0] == 200 and owner[1]["workspace"]["new"] is False
    assert len(registry.live()) == 1


def test_http_invented_session_id_is_refused_before_the_tool(docker, registry, settings, monkeypatch):
    async def body(h):
        await h.open("token-A")
        return await h.shell("echo x", sid="0123456789abcdef0123456789abcdef")
    status, _ = run_http(registry, monkeypatch, body)
    assert status == 404
    assert docker.commands == []


def test_http_modern_request_with_session_header_gets_no_workspace(docker, registry, settings, monkeypatch):
    async def body(h):
        sid = await h.open("token-A")
        return await h.shell("ls /tmp", sid=sid, version="2026-07-28",
                             headers=[("mcp-method", "tools/call"), ("mcp-name", "shell")],
                             meta={"io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                                   "io.modelcontextprotocol/clientCapabilities": {},
                                   "io.modelcontextprotocol/protocolVersion": "2026-07-28"})
    status, reply = run_http(registry, monkeypatch, body)
    assert status == 200 and reply["status"] == "success"
    assert "workspace" not in reply
    assert mounted_volume(docker.calls[0]) is None and docker.volumes == {}


def test_http_duplicate_authorization_uses_the_validated_token(docker, registry, settings, monkeypatch):
    """Le middleware valide le dernier en-tête ; la clé doit suivre ce jeton-là."""
    async def body(h):
        sid_b = await h.open("token-B")
        await h.shell("echo b", token="token-B", sid=sid_b)
        await h.shell("echo ambigu", token=None, sid=sid_b,
                      headers=[("authorization", "Bearer token-A"), ("authorization", "Bearer token-B")])
    run_http(registry, monkeypatch, body)
    normal, ambiguous = [mounted_volume(c) for c in docker.calls]
    assert normal == ambiguous
    assert len(registry.live()) == 1


# --- Docker réel --------------------------------------------------------------------------

REAL_IMAGE = os.environ.get("MCP_TOOLS_TEST_SANDBOX_IMAGE")


def docker_ready():
    if not REAL_IMAGE or shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", REAL_IMAGE], capture_output=True)
    return probe.returncode == 0


real_docker = pytest.mark.skipif(not docker_ready(), reason="MCP_TOOLS_TEST_SANDBOX_IMAGE absente ou Docker indisponible")


def docker_exists(kind, name):
    return subprocess.run(["docker", kind, "inspect", name], capture_output=True).returncode == 0


@real_docker
def test_real_docker_files_persist_in_session_and_stay_isolated(registry, settings, monkeypatch, clock):
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=8 * MiB)

    async def body(h):
        sid_a = await h.open("token-A")
        sid_a2 = await h.open("token-A")
        out = {
            "write": await h.shell("mkdir -p /tmp/src && echo secret-A > /tmp/src/f && echo ok", sid=sid_a),
            "read_same": await h.shell("cat /tmp/src/f", sid=sid_a),
            "cd_same": await h.shell("cd /tmp/src && cat f && pwd", sid=sid_a),
            "other_session": await h.shell("cat /tmp/src/f", sid=sid_a2),
            "other_token": await h.shell("cat /tmp/src/f", token="token-B", sid=sid_a),
            "size_bound": await h.shell("dd if=/dev/zero of=/tmp/big bs=1M count=20 2>&1 | tail -1; "
                                        "df -k /tmp | tail -1; truncate -s 0 /tmp/big", sid=sid_a),
            "no_exec": await h.shell("printf 'echo ran' > /tmp/s.sh && chmod +x /tmp/s.sh && /tmp/s.sh", sid=sid_a),
            "mounts": await h.shell("grep ' /tmp ' /proc/mounts; id -u", sid=sid_a),
            # En dernier : l'espace reste plein d'entrées, aucun nettoyage n'est nécessaire.
            "entries_bound": await h.shell("mkdir /tmp/n && cd /tmp/n && "
                                           "for i in $(seq 1 600); do : > f$i || { echo stop $i; break; }; done",
                                           sid=sid_a),
        }
        names = [(w.volume, w.holder) for w in registry.live()]
        clock.now += 10_000
        await registry.sweep(settings["value"])
        return out, names
    out, names = run_http(registry, monkeypatch, body)
    assert out["write"][1]["stdout"] == "ok\n" and out["write"][1]["workspace"]["new"] is True
    assert out["read_same"][1]["stdout"] == "secret-A\n"
    assert out["cd_same"][1]["stdout"] == "secret-A\n/tmp/src\n"
    assert out["other_session"][1]["returncode"] != 0 and "secret-A" not in out["other_session"][1]["stdout"]
    assert out["other_session"][1]["workspace"]["new"] is True
    assert out["other_token"] == (404, None)
    # 8 Mio : 512 entrées au plus, dont la racine et /tmp/src déjà présents.
    assert out["entries_bound"][1]["stdout"].startswith("stop ")
    assert int(out["entries_bound"][1]["stdout"].split()[1]) < 512
    assert "5460" in out["size_bound"][1]["stdout"]
    assert out["no_exec"][1]["returncode"] == 126
    mounts = out["mounts"][1]["stdout"]
    assert "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec" in mounts and "size=5460k" in mounts
    assert "nr_inodes=512" in mounts
    assert len(names) == 2
    for volume, holder in names:
        assert not docker_exists("volume", volume) and not docker_exists("container", holder)


@real_docker
def test_real_docker_paused_holder_keeps_the_workspace(registry, settings, monkeypatch, clock):
    """Docker liste un maintien en pause sous status=paused : l'inventaire de fin d'appel le voit présent."""
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=8 * MiB)

    async def body(h):
        sid = await h.open("token-A")
        write = await h.shell("echo kept > /tmp/f && echo ok", sid=sid)
        workspace = registry.live()[0]
        paused = subprocess.run(["docker", "pause", workspace.holder], capture_output=True).returncode
        during = await h.shell("cat /tmp/f", sid=sid)
        lost = workspace.holder_lost
        subprocess.run(["docker", "unpause", workspace.holder], capture_output=True)
        after = await h.shell("cat /tmp/f", sid=sid)
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return write, paused, during, lost, after
    write, paused, during, lost, after = run_http(registry, monkeypatch, body)
    assert write[1]["stdout"] == "ok\n" and paused == 0
    assert during[1]["stdout"] == "kept\n" and lost is False
    assert during[1]["workspace"]["persistent"] is True and during[1]["workspace"]["new"] is False
    assert after[1]["stdout"] == "kept\n" and after[1]["workspace"]["new"] is False
    assert registry.live() == []


WORST_CASE_WRITER = r"""
import os, sys
def stat():
    return {l.split()[0]: int(l.split()[1]) for l in open('/sys/fs/cgroup/memory.stat')}
data, stride = int(sys.argv[1]), sys.argv[2]
before = stat()
files = 0
try:
    while True:
        files += 1
        with open(f'/tmp/w/{files:05d}' + 'n' * 200, 'wb', buffering=0) as f:
            index = 0
            while True:
                offset = data - 4096 if stride == 'max' else index * int(stride) * 4096
                if offset + 4096 > data:
                    break
                f.seek(offset); f.write(b'x' * 4096); index += 1
                if stride == 'max':
                    break
except OSError:
    pass
after = stat()
print((after['shmem'] - before['shmem']) + (after['slab'] - before['slab']), after['slab'] - before['slab'])
"""


@real_docker
@pytest.mark.parametrize("stride", ["64", "4096", "max"])
def test_real_docker_kernel_memory_of_a_full_workspace_stays_within_its_budget(registry, settings, monkeypatch,
                                                                               clock, stride):
    """Mesure mémoire : pages, inodes, entrées et index des pages d'un fichier creux, au pire cas.

    Le conteneur d'appel porte toutes ces allocations dans son groupe de contrôle mémoire.
    """
    budget = 32 * MiB
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=budget, sandbox_memory="512m")
    data, _ = shell_workspace.tmpfs_layout(budget)
    script = WORST_CASE_WRITER.replace("'", "'\"'\"'")

    async def body(h):
        sid = await h.open("token-A")
        reply = await h.shell(f"mkdir /tmp/w && python3 -c '{script}' {data} {stride}",
                              sid=sid, extra={"timeout": 30})
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return reply
    status, reply = run_http(registry, monkeypatch, body)
    assert status == 200, reply
    used, slab = map(int, reply["stdout"].split())
    assert used <= budget
    if stride != "64":
        assert slab > 0


@real_docker
def test_real_docker_mcp_cancellation_removes_the_call_container(registry, settings, monkeypatch, clock):
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=8 * MiB)
    calls = ["docker", "ps", "-q", "--filter", f"label={shell_workspace.LABEL}={shell_workspace.CALL_ROLE}",
             "--filter", f"label={shell_workspace.INSTANCE_LABEL}={instance}"]

    async def body(h):
        sid = await h.open("token-A")
        call = asyncio.ensure_future(h.shell("sleep 25", sid=sid, extra={"timeout": 30}))
        for _ in range(200):
            if subprocess.run(calls, capture_output=True, text=True).stdout.split():
                break
            await asyncio.sleep(0.05)
        started = bool(subprocess.run(calls, capture_output=True, text=True).stdout.split())
        cancelled = await h.post({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                  "params": {"requestId": 1, "reason": "test"}}, sid=sid)
        gone_after = None
        for tenth in range(150):
            released = all(w.active == 0 for w in registry.live())
            if released and not subprocess.run(calls, capture_output=True, text=True).stdout.split():
                gone_after = tenth / 10
                break
            await asyncio.sleep(0.1)
        call.cancel()
        active = [w.active for w in registry.live()]
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return started, cancelled.status_code, gone_after, active
    started, status, gone_after, active = run_http(registry, monkeypatch, body)
    assert started and status == 202
    assert gone_after is not None and gone_after < 15
    assert active == [0]
    assert registry.live() == []


@real_docker
def test_real_docker_workspace_refuses_acls_and_extended_attributes(registry, settings, monkeypatch, clock):
    """Les ACL POSIX resteraient en mémoire noyau hors du budget de l'espace : setxattr est refusé."""
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=8 * MiB)
    acl = "\\x02\\x00\\x00\\x00\\x01\\x00\\x06\\x00\\xff\\xff\\xff\\xff\\x02\\x00\\x04\\x00\\xd2\\x04\\x00\\x00" \
          "\\x04\\x00\\x04\\x00\\xff\\xff\\xff\\xff\\x10\\x00\\x04\\x00\\xff\\xff\\xff\\xff\\x20\\x00\\x04\\x00\\xff\\xff\\xff\\xff"
    # setxattr par chemin, lsetxattr sans suivre le lien, fsetxattr par descripteur.
    probe = ("echo x > /tmp/f && python3 -c \"import os\n"
             "fd = os.open('/tmp/f', os.O_RDONLY)\n"
             "for how, target, follow in [('path', '/tmp/f', True), ('nofollow', '/tmp/f', False), ('fd', fd, True)]:\n"
             "    for name, value in [('system.posix_acl_access', b'" + acl + "'), ('user.k', b'v')]:\n"
             "        try:\n            os.setxattr(target, name, value, follow_symlinks=follow); print(how, name, 'ok')\n"
             "        except OSError as e:\n            print(how, name, e.errno)\" && cp -a /tmp/f /tmp/g && echo copied")

    async def body(h):
        sid = await h.open("token-A")
        reply = await h.shell(probe, sid=sid)
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return reply
    status, reply = run_http(registry, monkeypatch, body)
    assert status == 200 and reply["workspace"]["persistent"] is True
    expected = "".join(f"{how} {name} 95\n" for how in ("path", "nofollow", "fd")
                       for name in ("system.posix_acl_access", "user.k"))
    assert reply["stdout"] == expected + "copied\n"
    # Témoin : sans le filtre, le même tmpfs accepte l'ACL et l'attribut.
    plain = subprocess.run(["docker", "run", "--rm", "--network=none", "--user=sandbox:sandbox",
                            "--tmpfs=/tmp:size=8m", REAL_IMAGE, "bash", "-c", probe],
                           capture_output=True, text=True, timeout=60)
    assert plain.stdout == expected.replace(" 95", " ok") + "copied\n"



@real_docker
def test_real_docker_file_size_limit_applies_beyond_max_file_bytes(registry, settings, monkeypatch, clock):
    """Une page au-delà de max_file_bytes échoue en EFBIG alors que le volume a encore de la place."""
    instance = f"t72-{uuid.uuid4().hex[:8]}"
    settings["value"] = make_settings(sandbox_image=REAL_IMAGE, shell_workspace_instance=instance,
                                      shell_workspace_size_bytes=8 * MiB)
    data, _ = shell_workspace.tmpfs_layout(8 * MiB)
    probe = ("python3 -c \"import os, sys\n"
             "def write(offset):\n"
             "    with open('/tmp/s', 'wb') as f:\n"
             "        f.seek(offset); f.write(b'x' * 4096)\n"
             "write(int(sys.argv[1]) - 4096); print('inside ok')\n"
             "try:\n    write(int(sys.argv[1])); print('beyond ok')\n"
             "except OSError as e:\n    print('beyond', e.errno)\n"
             f"\" {data}")

    async def body(h):
        sid = await h.open("token-A")
        reply = await h.shell(probe, sid=sid)
        clock.now += 10_000
        await registry.sweep(settings["value"])
        await registry.stop()
        return reply
    status, reply = run_http(registry, monkeypatch, body)
    assert status == 200 and reply["workspace"]["max_file_bytes"] == data
    assert reply["stdout"] == "inside ok\nbeyond 27\n"
    # Témoin : le même tmpfs sans limite de taille de fichier accepte l'écriture au-delà.
    plain = subprocess.run(["docker", "run", "--rm", "--network=none", "--user=sandbox:sandbox",
                            "--tmpfs=/tmp:size=8m", REAL_IMAGE, "bash", "-c", probe],
                           capture_output=True, text=True, timeout=60)
    assert plain.stdout == "inside ok\nbeyond ok\n"
