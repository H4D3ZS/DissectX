"""CTF Platform Integration for automated flag submission and challenge management

This module integrates with popular CTF platforms:
- CTFd: Open-source CTF platform
- HackTheBox: Commercial CTF and pentesting platform

Features:
- Automatic flag submission
- Challenge download and parsing
- Real-time score tracking
- Leaderboard position monitoring
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import aiohttp
import json


class PlatformType(Enum):
    """Supported CTF platforms"""
    CTFD = "ctfd"
    HACKTHEBOX = "hackthebox"


class ChallengeStatus(Enum):
    """Challenge completion status"""
    UNSOLVED = "unsolved"
    SOLVED = "solved"
    ATTEMPTED = "attempted"


@dataclass
class Challenge:
    """CTF challenge information"""
    challenge_id: str
    name: str
    description: str
    category: str
    points: int
    status: ChallengeStatus
    target_url: Optional[str] = None
    files: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    solves: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Flag:
    """CTF flag information"""
    flag: str
    challenge_id: Optional[str] = None
    challenge_name: Optional[str] = None
    submitted: bool = False
    correct: bool = False
    points_awarded: int = 0
    submission_time: Optional[datetime] = None


@dataclass
class ScoreInfo:
    """User/team score information"""
    score: int
    rank: int
    total_teams: int
    solved_challenges: int
    total_challenges: int
    last_solve_time: Optional[datetime] = None


class CTFPlatformIntegration:
    """
    Integration with CTF platforms for automated flag submission and challenge management.
    
    Supports:
    - CTFd platform
    - HackTheBox platform
    - Automatic flag submission
    - Challenge download and parsing
    - Real-time score tracking
    """
    
    def __init__(
        self,
        platform_type: PlatformType,
        base_url: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize CTF platform integration.
        
        Args:
            platform_type: Type of CTF platform
            base_url: Base URL of the platform
            api_token: API token for authentication (preferred)
            username: Username for authentication (fallback)
            password: Password for authentication (fallback)
        """
        self.platform_type = platform_type
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.username = username
        self.password = password
        self.session: Optional[aiohttp.ClientSession] = None
        self._authenticated = False
        
        # Flag patterns for automatic detection
        self.flag_patterns = [
            r'CTF\{[^\}]+\}',
            r'FLAG\{[^\}]+\}',
            r'HTB\{[^\}]+\}',
            r'flag\{[^\}]+\}',
            r'[A-Za-z0-9]{32}',  # MD5-like flags
            r'[A-Za-z0-9_-]{20,}',  # Generic long strings
        ]
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def connect(self):
        """Establish connection to the platform"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        
        # Authenticate
        if not self._authenticated:
            await self._authenticate()
    
    async def close(self):
        """Close connection to the platform"""
        if self.session:
            await self.session.close()
            self.session = None
        self._authenticated = False
    
    async def _authenticate(self):
        """Authenticate with the platform"""
        if self.platform_type == PlatformType.CTFD:
            await self._authenticate_ctfd()
        elif self.platform_type == PlatformType.HACKTHEBOX:
            await self._authenticate_htb()
    
    async def _authenticate_ctfd(self):
        """Authenticate with CTFd platform"""
        if self.api_token:
            # Use API token authentication
            self.session.headers.update({
                'Authorization': f'Token {self.api_token}',
                'Content-Type': 'application/json'
            })
            self._authenticated = True
        elif self.username and self.password:
            # Use username/password authentication
            login_url = f"{self.base_url}/api/v1/login"
            data = {
                'name': self.username,
                'password': self.password
            }
            
            async with self.session.post(login_url, json=data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    if result.get('success'):
                        self._authenticated = True
                    else:
                        raise ValueError(f"CTFd authentication failed: {result.get('errors')}")
                else:
                    raise ValueError(f"CTFd authentication failed with status {resp.status}")
        else:
            raise ValueError("Either api_token or username/password must be provided")
    
    async def _authenticate_htb(self):
        """Authenticate with HackTheBox platform"""
        if self.api_token:
            # Use API token authentication
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            })
            self._authenticated = True
        elif self.username and self.password:
            # Use username/password authentication
            login_url = f"{self.base_url}/api/v4/login"
            data = {
                'email': self.username,
                'password': self.password
            }
            
            async with self.session.post(login_url, json=data) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    token = result.get('message', {}).get('access_token')
                    if token:
                        self.api_token = token
                        self.session.headers.update({
                            'Authorization': f'Bearer {token}',
                            'Content-Type': 'application/json'
                        })
                        self._authenticated = True
                    else:
                        raise ValueError("HackTheBox authentication failed: no token received")
                else:
                    raise ValueError(f"HackTheBox authentication failed with status {resp.status}")
        else:
            raise ValueError("Either api_token or username/password must be provided")
    
    async def submit_flag(self, flag: str, challenge_id: Optional[str] = None) -> Flag:
        """
        Submit a flag to the platform.
        
        Args:
            flag: Flag string to submit
            challenge_id: Optional challenge ID (required for some platforms)
            
        Returns:
            Flag object with submission result
        """
        if not self._authenticated:
            await self._authenticate()
        
        if self.platform_type == PlatformType.CTFD:
            return await self._submit_flag_ctfd(flag, challenge_id)
        elif self.platform_type == PlatformType.HACKTHEBOX:
            return await self._submit_flag_htb(flag, challenge_id)
        else:
            raise ValueError(f"Unsupported platform: {self.platform_type}")
    
    async def _submit_flag_ctfd(self, flag: str, challenge_id: Optional[str]) -> Flag:
        """Submit flag to CTFd platform"""
        submit_url = f"{self.base_url}/api/v1/challenges/attempt"
        
        data = {
            'challenge_id': challenge_id,
            'submission': flag
        }
        
        async with self.session.post(submit_url, json=data) as resp:
            result = await resp.json()
            
            flag_obj = Flag(
                flag=flag,
                challenge_id=challenge_id,
                submitted=True,
                submission_time=datetime.now()
            )
            
            if result.get('success'):
                data = result.get('data', {})
                flag_obj.correct = data.get('status') == 'correct'
                
                if flag_obj.correct:
                    # Get challenge info for points
                    challenge = await self.get_challenge(challenge_id)
                    if challenge:
                        flag_obj.points_awarded = challenge.points
                        flag_obj.challenge_name = challenge.name
            else:
                flag_obj.correct = False
            
            return flag_obj
    
    async def _submit_flag_htb(self, flag: str, challenge_id: Optional[str]) -> Flag:
        """Submit flag to HackTheBox platform"""
        if not challenge_id:
            raise ValueError("challenge_id is required for HackTheBox")
        
        submit_url = f"{self.base_url}/api/v4/challenge/own"
        
        data = {
            'challenge_id': int(challenge_id),
            'flag': flag
        }
        
        async with self.session.post(submit_url, json=data) as resp:
            result = await resp.json()
            
            flag_obj = Flag(
                flag=flag,
                challenge_id=challenge_id,
                submitted=True,
                submission_time=datetime.now()
            )
            
            if resp.status == 200:
                flag_obj.correct = result.get('message') == 'Correct flag!'
                if flag_obj.correct:
                    flag_obj.points_awarded = result.get('points', 0)
            else:
                flag_obj.correct = False
            
            return flag_obj
    
    async def get_challenges(self) -> List[Challenge]:
        """
        Get list of all challenges.
        
        Returns:
            List of Challenge objects
        """
        if not self._authenticated:
            await self._authenticate()
        
        if self.platform_type == PlatformType.CTFD:
            return await self._get_challenges_ctfd()
        elif self.platform_type == PlatformType.HACKTHEBOX:
            return await self._get_challenges_htb()
        else:
            raise ValueError(f"Unsupported platform: {self.platform_type}")
    
    async def _get_challenges_ctfd(self) -> List[Challenge]:
        """Get challenges from CTFd platform"""
        challenges_url = f"{self.base_url}/api/v1/challenges"
        
        async with self.session.get(challenges_url) as resp:
            result = await resp.json()
            
            challenges = []
            if result.get('success'):
                for chal_data in result.get('data', []):
                    challenge = Challenge(
                        challenge_id=str(chal_data['id']),
                        name=chal_data['name'],
                        description=chal_data.get('description', ''),
                        category=chal_data.get('category', 'Unknown'),
                        points=chal_data.get('value', 0),
                        status=ChallengeStatus.SOLVED if chal_data.get('solved_by_me') else ChallengeStatus.UNSOLVED,
                        solves=chal_data.get('solves', 0),
                        tags=chal_data.get('tags', [])
                    )
                    challenges.append(challenge)
            
            return challenges
    
    async def _get_challenges_htb(self) -> List[Challenge]:
        """Get challenges from HackTheBox platform"""
        challenges_url = f"{self.base_url}/api/v4/challenge/list"
        
        async with self.session.get(challenges_url) as resp:
            result = await resp.json()
            
            challenges = []
            for chal_data in result.get('data', []):
                challenge = Challenge(
                    challenge_id=str(chal_data['id']),
                    name=chal_data['name'],
                    description=chal_data.get('description', ''),
                    category=chal_data.get('category_name', 'Unknown'),
                    points=chal_data.get('points', 0),
                    status=ChallengeStatus.SOLVED if chal_data.get('authUserSolve') else ChallengeStatus.UNSOLVED,
                    solves=chal_data.get('solves', 0),
                    tags=chal_data.get('tags', [])
                )
                challenges.append(challenge)
            
            return challenges
    
    async def get_challenge(self, challenge_id: str) -> Optional[Challenge]:
        """
        Get detailed information about a specific challenge.
        
        Args:
            challenge_id: Challenge ID
            
        Returns:
            Challenge object or None if not found
        """
        if not self._authenticated:
            await self._authenticate()
        
        if self.platform_type == PlatformType.CTFD:
            return await self._get_challenge_ctfd(challenge_id)
        elif self.platform_type == PlatformType.HACKTHEBOX:
            return await self._get_challenge_htb(challenge_id)
        else:
            raise ValueError(f"Unsupported platform: {self.platform_type}")
    
    async def _get_challenge_ctfd(self, challenge_id: str) -> Optional[Challenge]:
        """Get challenge details from CTFd"""
        challenge_url = f"{self.base_url}/api/v1/challenges/{challenge_id}"
        
        async with self.session.get(challenge_url) as resp:
            if resp.status != 200:
                return None
            
            result = await resp.json()
            if not result.get('success'):
                return None
            
            chal_data = result.get('data', {})
            
            # Extract target URL from description if present
            target_url = self._extract_url_from_text(chal_data.get('description', ''))
            
            challenge = Challenge(
                challenge_id=challenge_id,
                name=chal_data['name'],
                description=chal_data.get('description', ''),
                category=chal_data.get('category', 'Unknown'),
                points=chal_data.get('value', 0),
                status=ChallengeStatus.SOLVED if chal_data.get('solved_by_me') else ChallengeStatus.UNSOLVED,
                target_url=target_url,
                files=chal_data.get('files', []),
                hints=[h.get('content', '') for h in chal_data.get('hints', [])],
                tags=chal_data.get('tags', []),
                solves=chal_data.get('solves', 0)
            )
            
            return challenge
    
    async def _get_challenge_htb(self, challenge_id: str) -> Optional[Challenge]:
        """Get challenge details from HackTheBox"""
        challenge_url = f"{self.base_url}/api/v4/challenge/info/{challenge_id}"
        
        async with self.session.get(challenge_url) as resp:
            if resp.status != 200:
                return None
            
            result = await resp.json()
            chal_data = result.get('data', {})
            
            # Extract target URL from description
            target_url = self._extract_url_from_text(chal_data.get('description', ''))
            
            challenge = Challenge(
                challenge_id=challenge_id,
                name=chal_data['name'],
                description=chal_data.get('description', ''),
                category=chal_data.get('category_name', 'Unknown'),
                points=chal_data.get('points', 0),
                status=ChallengeStatus.SOLVED if chal_data.get('authUserSolve') else ChallengeStatus.UNSOLVED,
                target_url=target_url,
                files=chal_data.get('download', []),
                solves=chal_data.get('solves', 0),
                tags=chal_data.get('tags', [])
            )
            
            return challenge
    
    async def download_challenge(self, challenge_id: str) -> Challenge:
        """
        Download challenge and auto-configure target settings.
        
        Args:
            challenge_id: Challenge ID
            
        Returns:
            Challenge object with parsed information
        """
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            raise ValueError(f"Challenge {challenge_id} not found")
        
        return challenge
    
    async def get_score(self) -> ScoreInfo:
        """
        Get current score and ranking.
        
        Returns:
            ScoreInfo object with current standings
        """
        if not self._authenticated:
            await self._authenticate()
        
        if self.platform_type == PlatformType.CTFD:
            return await self._get_score_ctfd()
        elif self.platform_type == PlatformType.HACKTHEBOX:
            return await self._get_score_htb()
        else:
            raise ValueError(f"Unsupported platform: {self.platform_type}")
    
    async def _get_score_ctfd(self) -> ScoreInfo:
        """Get score from CTFd platform"""
        # Get user info
        me_url = f"{self.base_url}/api/v1/users/me"
        async with self.session.get(me_url) as resp:
            result = await resp.json()
            user_data = result.get('data', {})
            user_id = user_data.get('id')
        
        # Get scoreboard
        scoreboard_url = f"{self.base_url}/api/v1/scoreboard"
        async with self.session.get(scoreboard_url) as resp:
            result = await resp.json()
            standings = result.get('data', [])
        
        # Find user's rank
        rank = 0
        score = 0
        for i, entry in enumerate(standings, 1):
            if entry.get('account_id') == user_id:
                rank = i
                score = entry.get('score', 0)
                break
        
        # Get challenges
        challenges = await self.get_challenges()
        solved = sum(1 for c in challenges if c.status == ChallengeStatus.SOLVED)
        
        return ScoreInfo(
            score=score,
            rank=rank,
            total_teams=len(standings),
            solved_challenges=solved,
            total_challenges=len(challenges)
        )
    
    async def _get_score_htb(self) -> ScoreInfo:
        """Get score from HackTheBox platform"""
        # Get user profile
        profile_url = f"{self.base_url}/api/v4/user/profile"
        async with self.session.get(profile_url) as resp:
            result = await resp.json()
            profile_data = result.get('data', {})
        
        score = profile_data.get('points', 0)
        rank = profile_data.get('rank', 0)
        
        # Get challenges
        challenges = await self.get_challenges()
        solved = sum(1 for c in challenges if c.status == ChallengeStatus.SOLVED)
        
        return ScoreInfo(
            score=score,
            rank=rank,
            total_teams=0,  # HTB doesn't provide total teams in API
            solved_challenges=solved,
            total_challenges=len(challenges)
        )
    
    async def get_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get leaderboard standings.
        
        Args:
            limit: Number of top entries to return
            
        Returns:
            List of leaderboard entries
        """
        if not self._authenticated:
            await self._authenticate()
        
        if self.platform_type == PlatformType.CTFD:
            return await self._get_leaderboard_ctfd(limit)
        elif self.platform_type == PlatformType.HACKTHEBOX:
            return await self._get_leaderboard_htb(limit)
        else:
            raise ValueError(f"Unsupported platform: {self.platform_type}")
    
    async def _get_leaderboard_ctfd(self, limit: int) -> List[Dict[str, Any]]:
        """Get leaderboard from CTFd"""
        scoreboard_url = f"{self.base_url}/api/v1/scoreboard"
        
        async with self.session.get(scoreboard_url) as resp:
            result = await resp.json()
            standings = result.get('data', [])[:limit]
            
            leaderboard = []
            for i, entry in enumerate(standings, 1):
                leaderboard.append({
                    'rank': i,
                    'name': entry.get('name', 'Unknown'),
                    'score': entry.get('score', 0),
                    'account_id': entry.get('account_id')
                })
            
            return leaderboard
    
    async def _get_leaderboard_htb(self, limit: int) -> List[Dict[str, Any]]:
        """Get leaderboard from HackTheBox"""
        leaderboard_url = f"{self.base_url}/api/v4/rankings/users"
        
        async with self.session.get(leaderboard_url, params={'limit': limit}) as resp:
            result = await resp.json()
            standings = result.get('data', [])
            
            leaderboard = []
            for entry in standings:
                leaderboard.append({
                    'rank': entry.get('rank', 0),
                    'name': entry.get('name', 'Unknown'),
                    'score': entry.get('points', 0),
                    'account_id': entry.get('id')
                })
            
            return leaderboard
    
    def _extract_url_from_text(self, text: str) -> Optional[str]:
        """Extract URL from text (description, etc.)"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        match = re.search(url_pattern, text)
        return match.group(0) if match else None
    
    def detect_flag(self, text: str) -> List[str]:
        """
        Detect potential flags in text using common patterns.
        
        Args:
            text: Text to search for flags
            
        Returns:
            List of potential flags found
        """
        flags = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text)
            flags.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_flags = []
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)
        
        return unique_flags
