"""Team collaboration for multi-user CTF competitions

This module provides real-time collaboration features:
- Team creation and member management
- Workspace and finding sharing
- Real-time finding broadcasts via WebSocket
- Attack synchronization to prevent duplicate work
- Session sharing between team members
- Shared activity feed
"""

import asyncio
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


class ActivityType(Enum):
    """Types of team activities"""
    FINDING_DISCOVERED = "finding_discovered"
    CHALLENGE_STARTED = "challenge_started"
    CHALLENGE_COMPLETED = "challenge_completed"
    FLAG_SUBMITTED = "flag_submitted"
    SESSION_SHARED = "session_shared"
    WORKSPACE_UPDATED = "workspace_updated"
    MEMBER_JOINED = "member_joined"
    MEMBER_LEFT = "member_left"


@dataclass
class TeamMember:
    """Team member information"""
    member_id: str
    username: str
    email: Optional[str] = None
    role: str = "member"  # member, leader
    joined_at: datetime = field(default_factory=_utc_now)
    is_online: bool = False
    current_task: Optional[str] = None


@dataclass
class Team:
    """Team information"""
    team_id: str
    name: str
    description: str = ""
    created_at: datetime = field(default_factory=_utc_now)
    members: List[TeamMember] = field(default_factory=list)
    shared_workspaces: List[str] = field(default_factory=list)
    shared_findings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Activity:
    """Team activity entry"""
    activity_id: str
    team_id: str
    member_id: str
    member_username: str
    activity_type: ActivityType
    description: str
    timestamp: datetime = field(default_factory=_utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskLock:
    """Distributed lock for preventing duplicate work"""
    task_id: str
    member_id: str
    member_username: str
    locked_at: datetime
    expires_at: datetime
    resource: str  # URL, endpoint, etc.


class TeamCollaboration:
    """
    Team collaboration system for multi-user CTF competitions.
    
    Provides:
    - Team management
    - Real-time finding broadcasts
    - Attack synchronization
    - Session sharing
    - Activity tracking
    """
    
    def __init__(self):
        """Initialize team collaboration system"""
        self.teams: Dict[str, Team] = {}
        self.activities: Dict[str, List[Activity]] = defaultdict(list)
        self.task_locks: Dict[str, TaskLock] = {}
        self.websocket_connections: Dict[str, Set[Any]] = defaultdict(set)
        self._lock = asyncio.Lock()
    
    def create_team(
        self,
        name: str,
        description: str = "",
        creator_id: str = None,
        creator_username: str = None
    ) -> Team:
        """
        Create a new team.
        
        Args:
            name: Team name
            description: Team description
            creator_id: ID of team creator
            creator_username: Username of team creator
            
        Returns:
            Team object
        """
        team_id = str(uuid.uuid4())
        
        team = Team(
            team_id=team_id,
            name=name,
            description=description
        )
        
        # Add creator as team leader
        if creator_id and creator_username:
            creator = TeamMember(
                member_id=creator_id,
                username=creator_username,
                role="leader",
                is_online=True
            )
            team.members.append(creator)
        
        self.teams[team_id] = team
        
        # Log activity
        if creator_id:
            self._log_activity(
                team_id=team_id,
                member_id=creator_id,
                member_username=creator_username,
                activity_type=ActivityType.MEMBER_JOINED,
                description=f"{creator_username} created the team"
            )
        
        return team
    
    def get_team(self, team_id: str) -> Optional[Team]:
        """
        Get team by ID.
        
        Args:
            team_id: Team ID
            
        Returns:
            Team object or None
        """
        return self.teams.get(team_id)
    
    def add_member(
        self,
        team_id: str,
        member_id: str,
        username: str,
        email: Optional[str] = None,
        role: str = "member"
    ) -> bool:
        """
        Add a member to a team.
        
        Args:
            team_id: Team ID
            member_id: Member ID
            username: Member username
            email: Member email
            role: Member role
            
        Returns:
            True if successful
        """
        team = self.teams.get(team_id)
        if not team:
            return False
        
        # Check if member already exists
        if any(m.member_id == member_id for m in team.members):
            return False
        
        member = TeamMember(
            member_id=member_id,
            username=username,
            email=email,
            role=role,
            is_online=True
        )
        
        team.members.append(member)
        
        # Log activity
        self._log_activity(
            team_id=team_id,
            member_id=member_id,
            member_username=username,
            activity_type=ActivityType.MEMBER_JOINED,
            description=f"{username} joined the team"
        )
        
        return True
    
    def remove_member(self, team_id: str, member_id: str) -> bool:
        """
        Remove a member from a team.
        
        Args:
            team_id: Team ID
            member_id: Member ID
            
        Returns:
            True if successful
        """
        team = self.teams.get(team_id)
        if not team:
            return False
        
        # Find and remove member
        member = None
        for m in team.members:
            if m.member_id == member_id:
                member = m
                break
        
        if member:
            team.members.remove(member)
            
            # Log activity
            self._log_activity(
                team_id=team_id,
                member_id=member_id,
                member_username=member.username,
                activity_type=ActivityType.MEMBER_LEFT,
                description=f"{member.username} left the team"
            )
            
            return True
        
        return False
    
    def update_member_status(
        self,
        team_id: str,
        member_id: str,
        is_online: bool = None,
        current_task: str = None
    ) -> bool:
        """
        Update member status.
        
        Args:
            team_id: Team ID
            member_id: Member ID
            is_online: Online status
            current_task: Current task description
            
        Returns:
            True if successful
        """
        team = self.teams.get(team_id)
        if not team:
            return False
        
        for member in team.members:
            if member.member_id == member_id:
                if is_online is not None:
                    member.is_online = is_online
                if current_task is not None:
                    member.current_task = current_task
                return True
        
        return False
    
    async def broadcast_finding(
        self,
        team_id: str,
        member_id: str,
        member_username: str,
        finding: Dict[str, Any]
    ):
        """
        Broadcast a finding to all team members.
        
        Args:
            team_id: Team ID
            member_id: Member who discovered the finding
            member_username: Username of discoverer
            finding: Finding data
        """
        team = self.teams.get(team_id)
        if not team:
            return
        
        # Add to shared findings
        finding_id = finding.get('finding_id')
        if finding_id and finding_id not in team.shared_findings:
            team.shared_findings.append(finding_id)
        
        # Log activity
        self._log_activity(
            team_id=team_id,
            member_id=member_id,
            member_username=member_username,
            activity_type=ActivityType.FINDING_DISCOVERED,
            description=f"{member_username} discovered: {finding.get('title', 'Unknown')}",
            metadata={'finding_id': finding_id}
        )
        
        # Broadcast to all connected WebSocket clients
        message = {
            'type': 'finding_discovered',
            'team_id': team_id,
            'member_id': member_id,
            'member_username': member_username,
            'finding': finding,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        await self._broadcast_to_team(team_id, message)
    
    async def acquire_task_lock(
        self,
        team_id: str,
        member_id: str,
        member_username: str,
        resource: str,
        duration_seconds: int = 300
    ) -> Optional[TaskLock]:
        """
        Acquire a distributed lock for a task to prevent duplicate work.
        
        Args:
            team_id: Team ID
            member_id: Member ID
            member_username: Member username
            resource: Resource being tested (URL, endpoint, etc.)
            duration_seconds: Lock duration in seconds
            
        Returns:
            TaskLock if acquired, None if already locked
        """
        async with self._lock:
            # Check if resource is already locked
            lock_key = f"{team_id}:{resource}"
            
            if lock_key in self.task_locks:
                existing_lock = self.task_locks[lock_key]
                # Check if lock has expired
                if datetime.now(timezone.utc) < existing_lock.expires_at:
                    # Lock still valid
                    return None
                # Lock expired, remove it
                del self.task_locks[lock_key]
            
            # Create new lock
            task_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            
            task_lock = TaskLock(
                task_id=task_id,
                member_id=member_id,
                member_username=member_username,
                locked_at=now,
                expires_at=datetime.fromtimestamp(
                    now.timestamp() + duration_seconds,
                    tz=timezone.utc
                ),
                resource=resource
            )
            
            self.task_locks[lock_key] = task_lock
            
            # Broadcast lock acquisition
            message = {
                'type': 'task_locked',
                'team_id': team_id,
                'member_id': member_id,
                'member_username': member_username,
                'resource': resource,
                'expires_at': task_lock.expires_at.isoformat()
            }
            
            await self._broadcast_to_team(team_id, message)
            
            return task_lock
    
    async def release_task_lock(
        self,
        team_id: str,
        resource: str
    ) -> bool:
        """
        Release a task lock.
        
        Args:
            team_id: Team ID
            resource: Resource that was locked
            
        Returns:
            True if lock was released
        """
        async with self._lock:
            lock_key = f"{team_id}:{resource}"
            
            if lock_key in self.task_locks:
                task_lock = self.task_locks[lock_key]
                del self.task_locks[lock_key]
                
                # Broadcast lock release
                message = {
                    'type': 'task_unlocked',
                    'team_id': team_id,
                    'member_id': task_lock.member_id,
                    'member_username': task_lock.member_username,
                    'resource': resource
                }
                
                await self._broadcast_to_team(team_id, message)
                
                return True
            
            return False
    
    def get_locked_tasks(self, team_id: str) -> List[TaskLock]:
        """
        Get all currently locked tasks for a team.
        
        Args:
            team_id: Team ID
            
        Returns:
            List of TaskLock objects
        """
        now = datetime.now(timezone.utc)
        locks = []
        
        for lock_key, task_lock in list(self.task_locks.items()):
            if lock_key.startswith(f"{team_id}:"):
                # Check if expired
                if now >= task_lock.expires_at:
                    del self.task_locks[lock_key]
                else:
                    locks.append(task_lock)
        
        return locks
    
    async def share_session(
        self,
        team_id: str,
        member_id: str,
        member_username: str,
        session_data: Dict[str, Any]
    ):
        """
        Share an authenticated session with team members.
        
        Args:
            team_id: Team ID
            member_id: Member sharing the session
            member_username: Username of sharer
            session_data: Session data to share
        """
        # Log activity
        self._log_activity(
            team_id=team_id,
            member_id=member_id,
            member_username=member_username,
            activity_type=ActivityType.SESSION_SHARED,
            description=f"{member_username} shared a session for {session_data.get('domain', 'unknown')}",
            metadata={'session_id': session_data.get('session_id')}
        )
        
        # Broadcast session
        message = {
            'type': 'session_shared',
            'team_id': team_id,
            'member_id': member_id,
            'member_username': member_username,
            'session': session_data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        await self._broadcast_to_team(team_id, message)
    
    def get_activities(
        self,
        team_id: str,
        limit: int = 50,
        activity_type: Optional[ActivityType] = None
    ) -> List[Activity]:
        """
        Get team activities.
        
        Args:
            team_id: Team ID
            limit: Maximum number of activities to return
            activity_type: Optional filter by activity type
            
        Returns:
            List of Activity objects
        """
        activities = self.activities.get(team_id, [])
        
        if activity_type:
            activities = [a for a in activities if a.activity_type == activity_type]
        
        # Return most recent activities
        return sorted(activities, key=lambda a: a.timestamp, reverse=True)[:limit]
    
    def _log_activity(
        self,
        team_id: str,
        member_id: str,
        member_username: str,
        activity_type: ActivityType,
        description: str,
        metadata: Dict[str, Any] = None
    ):
        """Log a team activity"""
        activity = Activity(
            activity_id=str(uuid.uuid4()),
            team_id=team_id,
            member_id=member_id,
            member_username=member_username,
            activity_type=activity_type,
            description=description,
            metadata=metadata or {}
        )
        
        self.activities[team_id].append(activity)
    
    async def register_websocket(self, team_id: str, websocket: Any):
        """
        Register a WebSocket connection for a team.
        
        Args:
            team_id: Team ID
            websocket: WebSocket connection
        """
        self.websocket_connections[team_id].add(websocket)
    
    async def unregister_websocket(self, team_id: str, websocket: Any):
        """
        Unregister a WebSocket connection.
        
        Args:
            team_id: Team ID
            websocket: WebSocket connection
        """
        if team_id in self.websocket_connections:
            self.websocket_connections[team_id].discard(websocket)
    
    async def _broadcast_to_team(self, team_id: str, message: Dict[str, Any]):
        """
        Broadcast a message to all team members via WebSocket.
        
        Args:
            team_id: Team ID
            message: Message to broadcast
        """
        if team_id not in self.websocket_connections:
            return
        
        # Convert message to JSON
        message_json = json.dumps(message)
        
        # Send to all connected clients
        disconnected = set()
        for websocket in self.websocket_connections[team_id]:
            try:
                await websocket.send_text(message_json)
            except Exception:
                # Mark for removal
                disconnected.add(websocket)
        
        # Remove disconnected clients
        for websocket in disconnected:
            self.websocket_connections[team_id].discard(websocket)
    
    def share_workspace(self, team_id: str, workspace_id: str) -> bool:
        """
        Share a workspace with the team.
        
        Args:
            team_id: Team ID
            workspace_id: Workspace ID
            
        Returns:
            True if successful
        """
        team = self.teams.get(team_id)
        if not team:
            return False
        
        if workspace_id not in team.shared_workspaces:
            team.shared_workspaces.append(workspace_id)
        
        return True
    
    def get_shared_workspaces(self, team_id: str) -> List[str]:
        """
        Get all shared workspaces for a team.
        
        Args:
            team_id: Team ID
            
        Returns:
            List of workspace IDs
        """
        team = self.teams.get(team_id)
        if not team:
            return []
        
        return team.shared_workspaces
    
    def get_shared_findings(self, team_id: str) -> List[str]:
        """
        Get all shared findings for a team.
        
        Args:
            team_id: Team ID
            
        Returns:
            List of finding IDs
        """
        team = self.teams.get(team_id)
        if not team:
            return []
        
        return team.shared_findings
