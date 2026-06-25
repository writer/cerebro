from __future__ import annotations

import asyncio


def ensure_event_loop() -> None:
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None

    if loop is None or loop.is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())


ensure_event_loop()
