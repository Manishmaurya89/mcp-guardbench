"""Small helper for calling async code from synchronous entry points (CLI, sync API routes)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor


def run_sync[T](factory: Callable[[], Awaitable[T]]) -> T:
    """Run ``factory()`` to completion and return its result.

    Uses ``asyncio.run`` directly when no loop is running in this thread. If one is (for example
    the call comes from an async test), the coroutine runs on a short-lived helper thread with its
    own loop, because ``asyncio.run`` cannot be nested.
    """

    async def _await() -> T:
        return await factory()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await())
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(_await())).result()
