"""WebSocket endpoints for real-time updates."""

from fastapi import APIRouter, WebSocket, Query
from typing import Optional

from cerebro.api.websocket import websocket_endpoint

router = APIRouter()


@router.websocket("/ws/events")
async def events_websocket(
    websocket: WebSocket,
    org_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """WebSocket endpoint for real-time event updates."""
    await websocket_endpoint(websocket, org_id, token)
