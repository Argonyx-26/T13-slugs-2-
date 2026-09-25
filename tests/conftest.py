import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mirage.alerting import Alerter, Broadcaster  # noqa: E402
from mirage.cli import initialise  # noqa: E402
from mirage.config import load_settings  # noqa: E402
from mirage.control import Health  # noqa: E402
from mirage.keys import load_keys  # noqa: E402
from mirage.placer import Placer  # noqa: E402
from mirage.registry import Registry  # noqa: E402
from mirage.response import MockEDR, Responder  # noqa: E402
from mirage.triage import Engine  # noqa: E402


def load_demo(name: str):
    module_name = f"demo_{name}"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "demo" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module  # dataclasses look their module up while the class is built
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not met in time")


class ServerThread:
    def __init__(self, app, port: int):
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", server_header=False))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> "ServerThread":
        self.thread.start()
        wait_for(lambda: self.server.started, timeout=10)
        return self

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(10)


@pytest.fixture
def settings(tmp_path):
    return load_settings(
        data_dir=tmp_path / "data", estate_root=tmp_path / "estate",
        control_port=free_port(), sensor_port=free_port(),
        selftest_interval=0.3, selftest_stale_after=1.5, spool_flush_interval=0.3,
        breaker_window=600.0, breaker_limit=2,
    )


@pytest.fixture
def estate(settings):
    load_demo("build_estate").build(settings.estate_root, allow_outside_project=True)
    return settings.estate_root


@pytest.fixture
def registry(settings, estate):
    registry = Registry(settings.db_path)
    initialise(settings, registry)
    yield registry
    registry.close()


@pytest.fixture
def keys(settings, registry):
    return load_keys(settings.key_path)


@pytest.fixture
def deployed(settings, registry, keys):
    Placer(settings, registry, keys).deploy()
    return {p["host"] + ":" + p["rel_path"]: p for p in registry.list_placements()}


@pytest.fixture
def engine(settings, registry, keys, deployed):
    alerter = Alerter(settings, Broadcaster(), out=lambda line: None)
    responder = Responder(settings, registry, MockEDR(registry), alerter)
    return Engine(settings, registry, keys, responder, alerter, Health(settings, alerter), own_pids=lambda: {4242})
