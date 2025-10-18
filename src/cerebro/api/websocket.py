"""WebSocket support for real-time updates."""

import json
import logging
from typing import Dict, Set, Optional, Any
from datetime import datetime
from uuid import UUID, uuid4

from fastapi import WebSocket, WebSocketDisconnect, Query

from cerebro.api.auth import TokenData
from cerebro.core.database import async_session_factory
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.metrics.auth_metrics import auth_metrics
from cerebro.metrics.jwt_metrics import jwt_metrics

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        # Organization-based connection pools
        self.org_connections: Dict[str, Set[WebSocket]] = {}
        # Global connections (no org filter)
        self.global_connections: Set[WebSocket] = set()
        
    async def connect(self, websocket: WebSocket, org_id: Optional[str] = None):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        
        if org_id:
            if org_id not in self.org_connections:
                self.org_connections[org_id] = set()
            self.org_connections[org_id].add(websocket)
            logger.info(f"WebSocket connected for org {org_id}")
        else:
            self.global_connections.add(websocket)
            logger.info("Global WebSocket connected")
    
    def disconnect(self, websocket: WebSocket, org_id: Optional[str] = None):
        """Remove a WebSocket connection."""
        if org_id and org_id in self.org_connections:
            self.org_connections[org_id].discard(websocket)
            if not self.org_connections[org_id]:
                del self.org_connections[org_id]
            logger.info(f"WebSocket disconnected for org {org_id}")
        else:
            self.global_connections.discard(websocket)
            logger.info("Global WebSocket disconnected")
    
    async def send_to_org(self, org_id: str, message: Dict[str, Any]):
        """Send message to all connections for an organization."""
        if org_id not in self.org_connections:
            return
        
        # Add trace ID and timestamp
        message.update({
            "trace_id": str(uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "org_id": org_id
        })
        
        message_text = json.dumps(message)
        connections_to_remove = set()
        
        for connection in self.org_connections[org_id]:
            try:
                await connection.send_text(message_text)
            except Exception as e:
                logger.warning(f"Failed to send message to WebSocket: {e}")
                connections_to_remove.add(connection)
        
        # Remove failed connections
        for connection in connections_to_remove:
            self.org_connections[org_id].discard(connection)
    
    async def send_to_all(self, message: Dict[str, Any]):
        """Send message to all connections."""
        # Add trace ID and timestamp
        message.update({
            "trace_id": str(uuid4()),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        message_text = json.dumps(message)
        
        # Send to global connections
        global_connections_to_remove = set()
        for connection in self.global_connections:
            try:
                await connection.send_text(message_text)
            except Exception as e:
                logger.warning(f"Failed to send message to global WebSocket: {e}")
                global_connections_to_remove.add(connection)
        
        # Remove failed global connections
        for connection in global_connections_to_remove:
            self.global_connections.discard(connection)
        
        # Send to all org-specific connections
        for org_id, connections in self.org_connections.items():
            connections_to_remove = set()
            for connection in connections:
                try:
                    await connection.send_text(message_text)
                except Exception as e:
                    logger.warning(f"Failed to send message to org {org_id} WebSocket: {e}")
                    connections_to_remove.add(connection)
            
            # Remove failed connections
            for connection in connections_to_remove:
                connections.discard(connection)
    
    def get_connection_count(self, org_id: Optional[str] = None) -> int:
        """Get number of active connections."""
        if org_id:
            return len(self.org_connections.get(org_id, set()))
        else:
            total = len(self.global_connections)
            for connections in self.org_connections.values():
                total += len(connections)
            return total


# Global connection manager
connection_manager = ConnectionManager()


def _token_payload_to_data(payload: Dict[str, Any]) -> TokenData:
    username = payload.get("sub")
    scopes = payload.get("scopes", [])
    raw_org = payload.get("org_id")
    token_type = payload.get("token_type")

    org_id: Optional[UUID] = None
    if isinstance(raw_org, str):
        try:
            org_id = UUID(raw_org)
        except ValueError:
            org_id = None

    return TokenData(
        username=str(username) if isinstance(username, str) else None,
        scopes=list(scopes) if isinstance(scopes, list) else [],
        org_id=org_id,
        token_type=str(token_type) if isinstance(token_type, str) else None,
    )


async def authenticate_websocket_token(token: Optional[str]) -> Optional[TokenData]:
    """Authenticate WebSocket connection using JWT token."""
    if not token:
        return None

    try:
        async with async_session_factory() as db:
            key_store = JWTKeyStore(db, metrics=jwt_metrics)
            await key_store.rotate_keys_if_needed()
            jwt_service = JWTService(key_store, metrics=jwt_metrics)
            payload = await jwt_service.verify_token(token, expected_type="access")
        return _token_payload_to_data(payload)
    except Exception as e:  # pragma: no cover - defensive path
        logger.warning(f"WebSocket authentication failed: {e}")
        return None


async def websocket_endpoint(
    websocket: WebSocket,
    org_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """WebSocket endpoint for real-time updates."""
    
    # Authenticate connection
    if token:
        token_data = await authenticate_websocket_token(token)
        if not token_data:
            await websocket.close(code=1008, reason="Authentication failed")
            auth_metrics.record_unauthorized_access("/ws/events", False)
            return

        username = token_data.username or "unknown"
        logger.info(f"Authenticated WebSocket connection for user {username}")
    else:
        # Allow unauthenticated connections for now (could be restricted in production)
        username = "anonymous"
        logger.info("Unauthenticated WebSocket connection")
    
    # Connect to appropriate channel
    await connection_manager.connect(websocket, org_id)
    
    try:
        # Send welcome message
        welcome_message = {
            "type": "connection_established",
            "org_id": org_id,
            "payload": {
                "user": username,
                "connection_time": datetime.utcnow().isoformat(),
                "org_filter": org_id is not None
            }
        }
        
        await websocket.send_text(json.dumps(welcome_message))
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages from client (heartbeat, etc.)
                data = await websocket.receive_text()
                
                # Handle client messages
                try:
                    client_message = json.loads(data)
                    await handle_client_message(websocket, client_message, org_id, username)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received from WebSocket: {data}")
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for org {org_id}")
    finally:
        connection_manager.disconnect(websocket, org_id)


async def handle_client_message(
    websocket: WebSocket,
    message: Dict[str, Any],
    org_id: Optional[str],
    username: str
):
    """Handle incoming messages from WebSocket client."""
    
    message_type = message.get("type")
    
    if message_type == "heartbeat":
        # Respond to heartbeat
        response = {
            "type": "heartbeat_ack",
            "payload": {"timestamp": datetime.utcnow().isoformat()}
        }
        await websocket.send_text(json.dumps(response))
        
    elif message_type == "subscribe":
        # Handle subscription to specific event types
        event_types = message.get("payload", {}).get("event_types", [])
        response = {
            "type": "subscription_ack",
            "payload": {
                "subscribed_events": event_types,
                "org_id": org_id
            }
        }
        await websocket.send_text(json.dumps(response))
        
    else:
        logger.warning(f"Unknown WebSocket message type: {message_type}")


class WebSocketNotifier:
    """Service for sending real-time notifications via WebSocket."""
    
    @staticmethod
    async def notify_finding_created(org_id: str, finding_data: Dict[str, Any]):
        """Notify of new finding creation."""
        message = {
            "type": "finding_created",
            "payload": finding_data
        }
        await connection_manager.send_to_org(org_id, message)
    
    @staticmethod
    async def notify_finding_updated(org_id: str, finding_data: Dict[str, Any]):
        """Notify of finding update."""
        message = {
            "type": "finding_updated", 
            "payload": finding_data
        }
        await connection_manager.send_to_org(org_id, message)

    @staticmethod
    async def notify_review_task_event(org_id: str, event_type: str, task_data: Dict[str, Any]):
        """Notify clients of review task lifecycle changes."""

        message = {
            "type": event_type,
            "payload": task_data,
        }
        await connection_manager.send_to_org(org_id, message)
    
    @staticmethod
    async def notify_rule_created(org_id: str, rule_data: Dict[str, Any]):
        """Notify of new rule creation."""
        message = {
            "type": "rule_created",
            "payload": rule_data
        }
        await connection_manager.send_to_org(org_id, message)
    
    @staticmethod
    async def notify_collection_completed(org_id: str, collection_data: Dict[str, Any]):
        """Notify of collection completion."""
        message = {
            "type": "collection_completed",
            "payload": collection_data
        }
        await connection_manager.send_to_org(org_id, message)
    
    @staticmethod
    async def notify_system_alert(alert_data: Dict[str, Any]):
        """Notify all connections of system alert."""
        message = {
            "type": "system_alert",
            "payload": alert_data
        }
        await connection_manager.send_to_all(message)


# Export WebSocket notifier for use in other modules
websocket_notifier = WebSocketNotifier()
