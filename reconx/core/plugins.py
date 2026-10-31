"""Small async plugin framework: bounded concurrency, per-source pacing, attribution."""
from __future__ import annotations
import asyncio, time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

@dataclass
class PluginResult:
    source: str
    kind: str
    items: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    message: str = ""

@dataclass
class PluginContext:
    client: Any
    config: dict[str, Any]
    target: str
    mode: str
    filters: dict[str, Any] = field(default_factory=dict)

class RateGate:
    def __init__(self, interval: float):
        self.interval = max(0.0, interval)
        self.lock = asyncio.Lock()
        self.last = 0.0
    async def wait(self):
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()

class Plugin:
    name = "base"
    modes: set[str] = set()
    rate_seconds = 0.0
    async def collect(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError

class PluginManager:
    def __init__(self, plugins: list[Plugin], concurrency: int = 8):
        self.plugins = plugins
        self.concurrency = max(1, concurrency)
        self.sem = asyncio.Semaphore(self.concurrency)
        self.gates = {p.name: RateGate(p.rate_seconds) for p in plugins}

    async def _run_one(self, plugin: Plugin, ctx: PluginContext) -> PluginResult:
        from reconx.utils.logger import step, ok, warn
        async with self.sem:
            await self.gates[plugin.name].wait()
            t0 = time.monotonic()
            step(plugin.name, f"Launching worker for {plugin.name} (mode: {ctx.mode})...")
            try:
                res = await plugin.collect(ctx)
                dur = time.monotonic() - t0
                if res.status == "ok":
                    ok(f"[{plugin.name}] Completed in {dur:.2f}s ({len(res.items)} items)")
                elif res.status == "not_configured":
                    step(plugin.name, f"Skipped: {res.message}")
                elif res.status in ("unavailable", "error"):
                    warn(f"[{plugin.name}] {res.status.upper()}: {res.message} ({dur:.2f}s)")
                return res
            except Exception as exc:
                dur = time.monotonic() - t0
                warn(f"[{plugin.name}] Failed after {dur:.2f}s: {type(exc).__name__}")
                return PluginResult(plugin.name, ctx.mode, [], "error", f"{type(exc).__name__}: {str(exc)[:180]}")

    async def run(self, ctx: PluginContext) -> list[PluginResult]:
        from reconx.utils.logger import info
        chosen = [p for p in self.plugins if ctx.mode in p.modes]
        info(f"Dispatching {len(chosen)} collection plugins across {self.concurrency} concurrent async workers...")
        return await asyncio.gather(*(self._run_one(p, ctx) for p in chosen))

def deduplicate(items: list[dict[str, Any]], key_fields=("url", "value", "host")) -> list[dict[str, Any]]:
    """Normalize duplicate URLs/values while retaining all source attribution."""
    merged: dict[str, dict[str, Any]] = {}
    for raw in items:
        item = dict(raw)
        key = ""
        for field_name in key_fields:
            value = item.get(field_name)
            if value:
                key = str(value).strip().rstrip("/").casefold()
                break
        if not key:
            key = repr(sorted(item.items())).casefold()
        if key not in merged:
            item["sources"] = sorted(set(item.get("sources", [item.get("source", "unknown")])) )
            merged[key] = item
        else:
            current = merged[key]
            current["sources"] = sorted(set(current.get("sources", [])) | set(item.get("sources", [item.get("source", "unknown")])) )
            for k, v in item.items():
                if k not in current or current[k] in (None, "", [], {}):
                    current[k] = v
    return list(merged.values())
