"""Consume the certstream-server-go lite WebSocket stream and batch-insert
certificate metadata into ClickHouse.

Writes only to ct.certs; a materialized view fans rows out into ct.domain_certs.
"""

import asyncio
import json
import logging
import os
import signal
from datetime import datetime, timezone

import clickhouse_connect
import websockets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ingester")

# --- Config (env) -----------------------------------------------------------
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CH_USER = os.environ.get("CLICKHOUSE_USER", "default")
CH_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CH_DB = os.environ.get("CLICKHOUSE_DB", "ct")
WS_URL = os.environ.get("CERTSTREAM_WS_URL", "ws://certstream:8080/")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "5000"))
BATCH_SECONDS = float(os.environ.get("BATCH_SECONDS", "2"))

# Column order must match the row tuples appended in _row().
COLUMNS = [
    "sha256", "seen", "not_before", "not_after", "all_domains", "subject_cn",
    "subject_o", "issuer_cn", "issuer_o", "signature_algorithm", "is_ca",
    "update_type", "source_name", "source_url", "source_type", "cert_index",
]


def _dt(epoch_seconds) -> datetime:
    """Unix seconds (int or float) -> aware UTC datetime."""
    return datetime.fromtimestamp(float(epoch_seconds or 0), tz=timezone.utc)


def _s(value) -> str:
    """Coalesce a possibly-null feed field to a string. Subject/issuer fields
    are nullable pointers in the certstream payload."""
    return "" if value is None else str(value)


def _hash_bytes(hexstr, n: int) -> bytes:
    """Colon-hex string (e.g. 'AA:BB:..') -> n raw bytes for FixedString(n)."""
    try:
        b = bytes.fromhex((hexstr or "").replace(":", ""))
    except ValueError:
        b = b""
    return b[:n].ljust(n, b"\x00")


def _row(data: dict) -> tuple:
    leaf = data.get("leaf_cert", {}) or {}
    subject = leaf.get("subject", {}) or {}
    issuer = leaf.get("issuer", {}) or {}
    source = data.get("source", {}) or {}
    return (
        _hash_bytes(leaf.get("sha256"), 32),
        _dt(data.get("seen")),
        _dt(leaf.get("not_before")),
        _dt(leaf.get("not_after")),
        list(leaf.get("all_domains") or []),
        _s(subject.get("CN")),
        _s(subject.get("O")),
        _s(issuer.get("CN")),
        _s(issuer.get("O")),
        _s(leaf.get("signature_algorithm")),
        1 if leaf.get("is_ca") else 0,
        _s(data.get("update_type")),
        _s(source.get("name")),
        _s(source.get("url")),
        _s(source.get("type")),
        int(data.get("cert_index") or 0),
    )


def connect_clickhouse():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER,
        password=CH_PASSWORD, database=CH_DB,
    )


class Batcher:
    """Buffers rows and flushes on size or time, whichever comes first."""

    def __init__(self, client):
        self.client = client
        self.rows: list[tuple] = []
        self.lock = asyncio.Lock()

    async def add(self, row: tuple):
        async with self.lock:
            self.rows.append(row)
            if len(self.rows) >= BATCH_SIZE:
                await self._flush_locked()

    async def flush(self):
        async with self.lock:
            await self._flush_locked()

    async def _flush_locked(self):
        if not self.rows:
            return
        batch, self.rows = self.rows, []
        # clickhouse-connect is synchronous; keep the event loop free.
        await asyncio.to_thread(
            self.client.insert, "certs", batch, column_names=COLUMNS,
        )
        log.info("inserted %d rows", len(batch))


async def _timed_flush(batcher: Batcher, stop: asyncio.Event):
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=BATCH_SECONDS)
        except asyncio.TimeoutError:
            pass
        await batcher.flush()


async def run():
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    client = connect_clickhouse()
    log.info("connected to ClickHouse at %s:%s/%s", CH_HOST, CH_PORT, CH_DB)
    batcher = Batcher(client)
    flusher = asyncio.create_task(_timed_flush(batcher, stop))

    backoff = 1
    try:
        while not stop.is_set():
            try:
                async with websockets.connect(
                    WS_URL, ping_interval=30, ping_timeout=30, max_size=None,
                ) as ws:
                    log.info("connected to certstream at %s", WS_URL)
                    backoff = 1
                    async for message in ws:
                        try:
                            payload = json.loads(message)
                        except json.JSONDecodeError:
                            continue
                        if payload.get("message_type") != "certificate_update":
                            continue
                        data = payload.get("data")
                        if data:
                            await batcher.add(_row(data))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # reconnect on any ws/network error
                if stop.is_set():
                    break
                log.warning("ws error: %s — reconnecting in %ss", exc, backoff)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 30)
    finally:
        stop.set()
        flusher.cancel()
        try:
            await flusher
        except asyncio.CancelledError:
            pass
        await batcher.flush()
        client.close()
        log.info("shutdown complete")


if __name__ == "__main__":
    asyncio.run(run())
