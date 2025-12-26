"""HTTP Request Handler with aiohttp and httpx support"""

import asyncio
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import aiohttp
import httpx

from src.vulnchain.core.http_models import Request, Response
from src.vulnchain.core.config import settings
from src.vulnchain.core.waf_profiles import apply_waf_profile


class RequestHandler:
    """
    Manages all HTTP/HTTPS communication with configurable options.
    Supports HTTP/1.1 and HTTP/2, custom headers, cookies, proxy configuration,
    redirect following, and retry logic with exponential backoff.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Request Handler.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.default_timeout = self.config.get("timeout", 30.0)
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_backoff_factor = self.config.get("retry_backoff_factor", 2.0)
        self.waf_bypass_profile: Optional[str] = None
        self._session_cache: Dict[str, aiohttp.ClientSession] = {}

    async def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        http2: bool = False,
    ) -> Response:
        """
        Send HTTP request with full control.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Optional custom headers
            data: Optional request body data
            cookies: Optional cookies
            proxy: Optional proxy URL
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow redirects
            http2: Whether to use HTTP/2

        Returns:
            Response object containing all response data

        Raises:
            aiohttp.ClientError: On network errors
            asyncio.TimeoutError: On timeout
        """
        # Create request object for tracking
        request = Request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            data=data,
            cookies=cookies or {},
            proxy=proxy,
            timeout=timeout,
            follow_redirects=follow_redirects,
            http2=http2,
        )

        # Apply WAF bypass profile if configured
        if self.waf_bypass_profile:
            try:
                request.headers = apply_waf_profile(self.waf_bypass_profile, request.headers)
            except ValueError:
                # Profile not found, fall back to old method
                request.headers.update(self._get_waf_bypass_headers(self.waf_bypass_profile))

        # Use httpx for HTTP/2 support, aiohttp for HTTP/1.1
        if http2:
            return await self._send_with_httpx(request)
        else:
            return await self._send_with_aiohttp(request)

    async def _send_with_aiohttp(self, request: Request) -> Response:
        """
        Send request using aiohttp (HTTP/1.1).

        Args:
            request: Request object

        Returns:
            Response object
        """
        start_time = time.time()
        history: List[Response] = []

        # Retry logic with exponential backoff
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                # Create session with appropriate settings
                timeout_obj = aiohttp.ClientTimeout(total=request.timeout)
                connector = aiohttp.TCPConnector(ssl=False)  # Allow self-signed certs

                async with aiohttp.ClientSession(
                    timeout=timeout_obj,
                    connector=connector,
                    cookies=request.cookies,
                ) as session:
                    # Prepare request kwargs
                    kwargs = {
                        "headers": request.headers,
                        "allow_redirects": request.follow_redirects,
                    }

                    if request.proxy:
                        kwargs["proxy"] = request.proxy

                    if request.data is not None:
                        if isinstance(request.data, dict):
                            kwargs["json"] = request.data
                        else:
                            kwargs["data"] = request.data

                    # Send request
                    async with session.request(
                        request.method, request.url, **kwargs
                    ) as resp:
                        # Read response body
                        body = await resp.read()
                        elapsed_time = time.time() - start_time

                        # Try to decode as text
                        try:
                            text = body.decode("utf-8", errors="replace")
                        except Exception:
                            text = body.decode("latin-1", errors="replace")

                        # Build response object
                        response = Response(
                            status_code=resp.status,
                            headers=dict(resp.headers),
                            body=body,
                            text=text,
                            elapsed_time=elapsed_time,
                            request=request,
                            history=history,
                        )

                        return response

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    # Exponential backoff
                    wait_time = self.retry_backoff_factor ** attempt
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    # Max retries reached, raise the exception
                    raise

        # Should not reach here, but just in case
        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected error in request handling")

    async def _send_with_httpx(self, request: Request) -> Response:
        """
        Send request using httpx (HTTP/2 support).

        Args:
            request: Request object

        Returns:
            Response object
        """
        start_time = time.time()
        history: List[Response] = []

        # Retry logic with exponential backoff
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                # Create client with HTTP/2 support
                async with httpx.AsyncClient(
                    http2=True,
                    timeout=request.timeout,
                    follow_redirects=request.follow_redirects,
                    verify=False,  # Allow self-signed certs
                    cookies=request.cookies,
                    proxies=request.proxy,
                ) as client:
                    # Prepare request kwargs
                    kwargs = {"headers": request.headers}

                    if request.data is not None:
                        if isinstance(request.data, dict):
                            kwargs["json"] = request.data
                        else:
                            kwargs["content"] = request.data

                    # Send request
                    resp = await client.request(
                        request.method, request.url, **kwargs
                    )

                    elapsed_time = time.time() - start_time

                    # Build response object
                    response = Response(
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.content,
                        text=resp.text,
                        elapsed_time=elapsed_time,
                        request=request,
                        history=history,
                    )

                    return response

            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    # Exponential backoff
                    wait_time = self.retry_backoff_factor ** attempt
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    # Max retries reached, raise the exception
                    raise

        # Should not reach here, but just in case
        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected error in request handling")

    async def send_batch(self, requests: List[Request]) -> List[Response]:
        """
        Send multiple requests concurrently.

        Args:
            requests: List of Request objects

        Returns:
            List of Response objects in the same order as requests
        """
        tasks = []
        for req in requests:
            task = self.send_request(
                method=req.method,
                url=req.url,
                headers=req.headers,
                data=req.data,
                cookies=req.cookies,
                proxy=req.proxy,
                timeout=req.timeout,
                follow_redirects=req.follow_redirects,
                http2=req.http2,
            )
            tasks.append(task)

        # Execute all requests concurrently
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error responses if needed
        result = []
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                # Create error response
                error_response = Response(
                    status_code=0,
                    headers={},
                    body=b"",
                    text=str(resp),
                    elapsed_time=0.0,
                    request=requests[i],
                    history=[],
                )
                result.append(error_response)
            else:
                result.append(resp)

        return result

    def apply_waf_bypass_profile(self, profile_name: str):
        """
        Apply WAF bypass header configuration.

        Args:
            profile_name: Name of the WAF bypass profile
        """
        self.waf_bypass_profile = profile_name

    def _get_waf_bypass_headers(self, profile_name: str) -> Dict[str, str]:
        """
        Get WAF bypass headers for a specific profile.

        Args:
            profile_name: Name of the profile

        Returns:
            Dictionary of headers to apply
        """
        # Common WAF bypass headers
        profiles = {
            "cloudflare": {
                "CF-Connecting-IP": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Host": "127.0.0.1",
            },
            "akamai": {
                "X-Forwarded-For": "127.0.0.1",
                "True-Client-IP": "127.0.0.1",
            },
            "aws_waf": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
            },
            "modsecurity": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
            },
            "generic": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
            },
        }

        return profiles.get(profile_name, profiles["generic"])

    async def close(self):
        """Close all cached sessions"""
        for session in self._session_cache.values():
            await session.close()
        self._session_cache.clear()

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
