"""WebSocket endpoints for real-time updates."""

import json
import logging
from typing import Dict, Set, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from fastapi.security import HTTPBearer
import asyncio

from cerebro.core.database import get_db
from cerebro.api.auth import verify_token, User, get_current_user
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()
logger = logging.getLogger(__name__)

# Store active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.user_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, org_id: Optional[str] = None, user_id: Optional[str] = None):
        """Accept WebSocket connection and store it."""
        await websocket.accept()
        
        # Store by organization for broadcasting
        if org_id:
            if org_id not in self.active_connections:
                self.active_connections[org_id] = set()
            self.active_connections[org_id].add(websocket)
            
        # Store by user for direct messaging
        if user_id:
            self.user_connections[user_id] = websocket
            
        logger.info(f"WebSocket connected for org={org_id}, user={user_id}")
        
    def disconnect(self, websocket: WebSocket, org_id: Optional[str] = None, user_id: Optional[str] = None):
        """Remove WebSocket connection."""
        if org_id and org_id in self.active_connections:
            self.active_connections[org_id].discard(websocket)
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]
                
        if user_id and user_id in self.user_connections:
            del self.user_connections[user_id]
            
        logger.info(f"WebSocket disconnected for org={org_id}, user={user_id}")
        
    async def send_personal_message(self, message: str, user_id: str):
        """Send a message to a specific user."""
        if user_id in self.user_connections:
            try:
                await self.user_connections[user_id].send_text(message)
            except Exception as e:
                logger.error(f"Failed to send message to user {user_id}: {e}")
                
    async def broadcast_to_org(self, message: str, org_id: str):
        """Send a message to all connections in an organization."""
        if org_id in self.active_connections:
            disconnected = set()
            
            for connection in self.active_connections[org_id].copy():
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to connection: {e}")
                    disconnected.add(connection)
                    
            # Clean up disconnected connections
            for connection in disconnected:
                self.active_connections[org_id].discard(connection)


manager = ConnectionManager()


def authenticate_websocket(token: str) -> Optional[Dict]:
    """Authenticate WebSocket connection using JWT token."""
    try:
        token_data = verify_token(token)
        return {
            "username": token_data.username,
            "scopes": token_data.scopes
        }
    except Exception as e:
        logger.error(f"WebSocket authentication failed: {e}")
        return None


@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    org_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time security events.
    
    Clients can connect to receive real-time updates for:
    - New findings
    - Finding status changes  
    - Rule updates
    - System alerts
    """
    
    # Authenticate connection
    user_info = None
    if token:
        user_info = authenticate_websocket(token)
        if not user_info:
            await websocket.close(code=4001, reason="Authentication failed")
            return
    
    user_id = user_info.get("username") if user_info else None
    
    # Connect WebSocket
    await manager.connect(websocket, org_id=org_id, user_id=user_id)
    
    try:
        # Send welcome message
        welcome_msg = {
            "type": "welcome",
            "message": "Connected to Cerebro events stream",
            "org_id": org_id,
            "user_id": user_id,
            "timestamp": asyncio.get_event_loop().time()
        }
        await websocket.send_text(json.dumps(welcome_msg))
        
        # Keep connection alive and listen for client messages
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "ping":
                    pong_msg = {
                        "type": "pong",
                        "timestamp": asyncio.get_event_loop().time()
                    }
                    await websocket.send_text(json.dumps(pong_msg))
                    
                elif message.get("type") == "subscribe":
                    # Handle subscription requests
                    topics = message.get("topics", [])
                    response = {
                        "type": "subscription_ack",
                        "topics": topics,
                        "message": f"Subscribed to {len(topics)} topics"
                    }
                    await websocket.send_text(json.dumps(response))
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received: {data}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, org_id=org_id, user_id=user_id)
        logger.info(f"WebSocket disconnected: org_id={org_id}, user_id={user_id}")
        
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, org_id=org_id, user_id=user_id)


@router.websocket("/ws/findings")
async def websocket_findings(
    websocket: WebSocket,
    org_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint specifically for findings updates.
    
    Provides real-time notifications for:
    - New findings discovered
    - Finding status changes (active -> suppressed, etc.)
    - Finding resolution updates
    """
    
    # Authenticate connection
    user_info = None
    if token:
        user_info = authenticate_websocket(token)
        if not user_info:
            await websocket.close(code=4001, reason="Authentication failed")
            return
    
    user_id = user_info.get("username") if user_info else None
    
    # Connect WebSocket
    await manager.connect(websocket, org_id=org_id, user_id=user_id)
    
    try:
        # Send welcome message
        welcome_msg = {
            "type": "findings_stream_connected",
            "message": "Connected to findings updates stream",
            "org_id": org_id,
            "user_id": user_id,
            "timestamp": asyncio.get_event_loop().time()
        }
        await websocket.send_text(json.dumps(welcome_msg))
        
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    pong_msg = {
                        "type": "pong", 
                        "stream": "findings",
                        "timestamp": asyncio.get_event_loop().time()
                    }
                    await websocket.send_text(json.dumps(pong_msg))
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received: {data}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, org_id=org_id, user_id=user_id)
        logger.info(f"Findings WebSocket disconnected: org_id={org_id}, user_id={user_id}")
        
    except Exception as e:
        logger.error(f"Findings WebSocket error: {e}")
        manager.disconnect(websocket, org_id=org_id, user_id=user_id)


# Utility functions for sending notifications

async def notify_new_finding(finding_data: dict, org_id: str):
    """Notify all connected clients about a new finding."""
    notification = {
        "type": "new_finding",
        "data": finding_data,
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.broadcast_to_org(json.dumps(notification), org_id)


async def notify_finding_status_change(finding_id: str, old_status: str, new_status: str, org_id: str):
    """Notify about finding status changes."""
    notification = {
        "type": "finding_status_change",
        "data": {
            "finding_id": finding_id,
            "old_status": old_status,
            "new_status": new_status
        },
        "timestamp": asyncio.get_event_loop().time()
    }
    await manager.broadcast_to_org(json.dumps(notification), org_id)


async def notify_system_alert(alert_type: str, message: str, org_id: Optional[str] = None):
    """Send system-wide alerts."""
    notification = {
        "type": "system_alert",
        "alert_type": alert_type,
        "message": message,
        "timestamp": asyncio.get_event_loop().time()
    }
    
    if org_id:
        await manager.broadcast_to_org(json.dumps(notification), org_id)
    else:
        # Broadcast to all organizations
        for org in manager.active_connections:
            await manager.broadcast_to_org(json.dumps(notification), org)


# Export manager for use in other modules
__all__ = ["router", "manager", "notify_new_finding", "notify_finding_status_change", "notify_system_alert"]
