"""WebSocket endpoints for real-time communication"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set, List
import asyncio
import json
from datetime import datetime

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages WebSocket connections for different channels"""
    
    def __init__(self):
        # Store active connections by channel
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "logs": set(),
            "fuzzing": set(),
            "oob": set(),
            "team": set()
        }
    
    async def connect(self, websocket: WebSocket, channel: str):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        self.active_connections[channel].add(websocket)
    
    def disconnect(self, websocket: WebSocket, channel: str):
        """Remove a WebSocket connection"""
        if channel in self.active_connections:
            self.active_connections[channel].discard(websocket)
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send a message to a specific connection"""
        await websocket.send_text(message)
    
    async def broadcast(self, message: str, channel: str):
        """Broadcast a message to all connections in a channel"""
        if channel in self.active_connections:
            disconnected = set()
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_text(message)
                except Exception:
                    disconnected.add(connection)
            
            # Remove disconnected clients
            for connection in disconnected:
                self.active_connections[channel].discard(connection)
    
    async def broadcast_json(self, data: dict, channel: str):
        """Broadcast JSON data to all connections in a channel"""
        message = json.dumps(data)
        await self.broadcast(message, channel)


# Global connection manager instance
manager = ConnectionManager()


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """
    WebSocket endpoint for real-time log streaming.
    
    Clients connect to receive log entries as they are generated.
    """
    await manager.connect(websocket, "logs")
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for testing
            await manager.send_personal_message(
                json.dumps({"type": "ack", "message": "Connected to logs stream"}),
                websocket
            )
    except WebSocketDisconnect:
        manager.disconnect(websocket, "logs")


@router.websocket("/ws/fuzzing")
async def websocket_fuzzing(websocket: WebSocket):
    """
    WebSocket endpoint for real-time fuzzing updates.
    
    Clients connect to receive fuzzing progress and results in real-time.
    """
    await manager.connect(websocket, "fuzzing")
    try:
        while True:
            data = await websocket.receive_text()
            
            # Handle client messages (e.g., filter updates)
            try:
                message = json.loads(data)
                if message.get("type") == "filter":
                    # Client is updating filters
                    await manager.send_personal_message(
                        json.dumps({"type": "filter_ack", "filters": message.get("filters")}),
                        websocket
                    )
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, "fuzzing")


@router.websocket("/ws/oob")
async def websocket_oob(websocket: WebSocket):
    """
    WebSocket endpoint for OOB callback notifications.
    
    Clients connect to receive out-of-band callback notifications in real-time.
    """
    await manager.connect(websocket, "oob")
    try:
        while True:
            data = await websocket.receive_text()
            
            await manager.send_personal_message(
                json.dumps({"type": "ack", "message": "Connected to OOB stream"}),
                websocket
            )
    except WebSocketDisconnect:
        manager.disconnect(websocket, "oob")


@router.websocket("/ws/team")
async def websocket_team(websocket: WebSocket):
    """
    WebSocket endpoint for team collaboration broadcasts.
    
    Clients connect to receive real-time updates about team member activities,
    findings, and shared resources.
    """
    await manager.connect(websocket, "team")
    try:
        while True:
            data = await websocket.receive_text()
            
            # Parse and broadcast team messages
            try:
                message = json.loads(data)
                
                # Add timestamp and broadcast to all team members
                message["timestamp"] = datetime.now().isoformat()
                await manager.broadcast_json(message, "team")
                
            except json.JSONDecodeError:
                await manager.send_personal_message(
                    json.dumps({"type": "error", "message": "Invalid JSON"}),
                    websocket
                )
    except WebSocketDisconnect:
        manager.disconnect(websocket, "team")


# Helper functions for broadcasting from other parts of the application

async def broadcast_log(log_entry: dict):
    """
    Broadcast a log entry to all connected clients.
    
    Args:
        log_entry: Log entry data
    """
    await manager.broadcast_json({
        "type": "log",
        "data": log_entry,
        "timestamp": datetime.now().isoformat()
    }, "logs")


async def broadcast_fuzzing_result(result: dict):
    """
    Broadcast a fuzzing result to all connected clients.
    
    Args:
        result: Fuzzing result data
    """
    await manager.broadcast_json({
        "type": "fuzzing_result",
        "data": result,
        "timestamp": datetime.now().isoformat()
    }, "fuzzing")


async def broadcast_oob_callback(callback: dict):
    """
    Broadcast an OOB callback to all connected clients.
    
    Args:
        callback: OOB callback data
    """
    await manager.broadcast_json({
        "type": "oob_callback",
        "data": callback,
        "timestamp": datetime.now().isoformat()
    }, "oob")


async def broadcast_team_activity(activity: dict):
    """
    Broadcast a team activity to all connected team members.
    
    Args:
        activity: Team activity data
    """
    await manager.broadcast_json({
        "type": "team_activity",
        "data": activity,
        "timestamp": datetime.now().isoformat()
    }, "team")


async def broadcast_team_finding(finding: dict):
    """
    Broadcast a new finding to all team members.
    
    Args:
        finding: Finding data
    """
    await manager.broadcast_json({
        "type": "team_finding",
        "data": finding,
        "timestamp": datetime.now().isoformat()
    }, "team")
