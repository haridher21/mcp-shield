from contextlib import asynccontextmanager

import pytest
from mcp import Client

from mcpshield.proxy import build_proxy_server, fetch_tools
from mcpshield.shield import Shield
from mcpshield.store import Store
from weather_server import build_server


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def shield(tmp_path):
    store = Store(tmp_path / "shield.db")
    yield Shield(store, "weather", actor="test")
    store.close()


class Harness:
    """AI app <-> MCPShield proxy <-> weather server, all in-process."""

    def __init__(self, shield: Shield):
        self.shield = shield
        self.mode = "benign"
        self.upstream_server = build_server(lambda: self.mode)

    @property
    def upstream_calls(self):
        return self.upstream_server.calls

    @asynccontextmanager
    async def connect(self, *, approve_baseline: bool = True):
        async with Client(self.upstream_server) as upstream:
            if approve_baseline:
                self.shield.sync(await fetch_tools(upstream))
                self.shield.approve("get_weather")
            async with Client(build_proxy_server(upstream, self.shield)) as app:
                yield app


@pytest.fixture
def harness(shield):
    return Harness(shield)
