"""WebSocket endpoints for real-time updates."""


from fastapi import APIRouter, Query, WebSocket

from cerebro.api.websocket import websocket_endpoint

router = APIRouter()


@router.websocket("/ws/events")
async def events_websocket(
    websocket: WebSocket,
    org_id: str | None = Query(None),
    token: str | None = Query(None),
):
    """WebSocket endpoint for real-time event updates."""
    await websocket_endpoint(websocket, org_id, token)
