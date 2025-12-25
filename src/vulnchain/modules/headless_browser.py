"""Headless browser module for JavaScript-heavy applications and client-side testing

This module implements:
- Playwright integration for browser automation
- JavaScript execution in controlled environment
- SPA (Single Page Application) testing with API interception
- Clickjacking testing with frame-busting bypass verification
- Client-side storage extraction (localStorage, sessionStorage, IndexedDB)
"""

import asyncio
import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

from src.vulnchain.core.request_handler import RequestHandler
from src.vulnchain.models.target import TargetConfig


class StorageType(Enum):
    """Types of client-side storage"""
    
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    INDEXED_DB = "indexedDB"
    COOKIES = "cookies"


@dataclass
class StorageData:
    """Client-side storage data"""
    
    storage_type: StorageType
    key: str
    value: Any
    domain: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APICall:
    """Intercepted API call from SPA"""
    
    url: str
    method: str
    headers: Dict[str, str]
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    timestamp: Optional[float] = None


@dataclass
class ClickjackingResult:
    """Result of clickjacking test"""
    
    is_vulnerable: bool
    frame_busting_present: bool
    frame_busting_bypassed: bool
    x_frame_options: Optional[str] = None
    csp_frame_ancestors: Optional[str] = None
    poc_html: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class BrowserResult:
    """Result of browser-based testing"""
    
    url: str
    success: bool
    rendered_html: Optional[str] = None
    screenshot: Optional[bytes] = None
    console_logs: List[str] = field(default_factory=list)
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    storage_data: List[StorageData] = field(default_factory=list)
    api_calls: List[APICall] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class HeadlessBrowser:
    """
    Headless browser integration for testing JavaScript-heavy applications.
    
    Provides:
    - Browser automation with Playwright
    - JavaScript execution in controlled environment
    - API call interception for SPAs
    - Clickjacking testing
    - Client-side storage extraction
    """
    
    def __init__(self, request_handler: RequestHandler):
        """
        Initialize headless browser module.
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
        self._playwright = None
        self._browser = None
        self._browser_type = "chromium"  # chromium, firefox, webkit
    
    async def _ensure_browser(self):
        """Ensure browser is initialized"""
        if self._browser is None:
            try:
                from playwright.async_api import async_playwright
                
                if self._playwright is None:
                    self._playwright = await async_playwright().start()
                
                # Launch browser
                if self._browser_type == "chromium":
                    self._browser = await self._playwright.chromium.launch(
                        headless=True,
                        args=['--no-sandbox', '--disable-setuid-sandbox']
                    )
                elif self._browser_type == "firefox":
                    self._browser = await self._playwright.firefox.launch(headless=True)
                elif self._browser_type == "webkit":
                    self._browser = await self._playwright.webkit.launch(headless=True)
                else:
                    raise ValueError(f"Unsupported browser type: {self._browser_type}")
            
            except ImportError:
                raise ImportError(
                    "Playwright not installed. Install with: pip install playwright && playwright install"
                )
    
    async def close(self):
        """Close browser and cleanup resources"""
        if self._browser:
            await self._browser.close()
            self._browser = None
        
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
    
    async def render_page(
        self,
        target: TargetConfig,
        wait_for_selector: Optional[str] = None,
        wait_time: float = 2.0,
        capture_screenshot: bool = True,
        capture_network: bool = True,
    ) -> BrowserResult:
        """
        Render a page with JavaScript execution.
        
        Args:
            target: Target configuration
            wait_for_selector: Optional CSS selector to wait for
            wait_time: Time to wait for page to load (seconds)
            capture_screenshot: Whether to capture screenshot
            capture_network: Whether to capture network requests
            
        Returns:
            BrowserResult with rendered content and metadata
        """
        await self._ensure_browser()
        
        result = BrowserResult(url=target.url, success=False)
        
        try:
            # Create new page
            context = await self._browser.new_context(
                ignore_https_errors=True,
                user_agent=target.custom_headers.get('User-Agent') if target.custom_headers else None,
            )
            
            page = await context.new_page()
            
            # Set up console log capture
            console_logs = []
            page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
            
            # Set up network request capture
            network_requests = []
            if capture_network:
                page.on("request", lambda request: network_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": request.headers,
                    "resource_type": request.resource_type,
                }))
            
            # Set custom headers if provided
            if target.custom_headers:
                await context.set_extra_http_headers(target.custom_headers)
            
            # Navigate to page
            response = await page.goto(target.url, wait_until="networkidle", timeout=30000)
            
            # Wait for specific selector if provided
            if wait_for_selector:
                await page.wait_for_selector(wait_for_selector, timeout=10000)
            else:
                # Wait for specified time
                await asyncio.sleep(wait_time)
            
            # Get rendered HTML
            rendered_html = await page.content()
            result.rendered_html = rendered_html
            
            # Capture screenshot
            if capture_screenshot:
                screenshot_bytes = await page.screenshot(full_page=True)
                result.screenshot = screenshot_bytes
            
            # Extract storage data
            storage_data = await self._extract_storage(page)
            result.storage_data = storage_data
            
            # Store console logs and network requests
            result.console_logs = console_logs
            result.network_requests = network_requests
            
            result.success = True
            result.metadata = {
                "status_code": response.status if response else None,
                "final_url": page.url,
            }
            
            await context.close()
        
        except Exception as e:
            result.error = f"Error rendering page: {str(e)}"
        
        return result
    
    async def execute_javascript(
        self,
        target: TargetConfig,
        javascript_code: str,
        wait_time: float = 1.0,
    ) -> BrowserResult:
        """
        Execute JavaScript code in browser context.
        
        Args:
            target: Target configuration
            javascript_code: JavaScript code to execute
            wait_time: Time to wait after execution (seconds)
            
        Returns:
            BrowserResult with execution results
        """
        await self._ensure_browser()
        
        result = BrowserResult(url=target.url, success=False)
        
        try:
            # Create new page
            context = await self._browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # Set up console log capture
            console_logs = []
            page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
            
            # Navigate to page
            await page.goto(target.url, wait_until="networkidle", timeout=30000)
            
            # Execute JavaScript
            js_result = await page.evaluate(javascript_code)
            
            # Wait for any async operations
            await asyncio.sleep(wait_time)
            
            # Get rendered HTML after execution
            rendered_html = await page.content()
            result.rendered_html = rendered_html
            
            # Store console logs
            result.console_logs = console_logs
            
            result.success = True
            result.metadata = {
                "javascript_result": js_result,
                "final_url": page.url,
            }
            
            await context.close()
        
        except Exception as e:
            result.error = f"Error executing JavaScript: {str(e)}"
        
        return result
    
    async def test_spa_with_interception(
        self,
        target: TargetConfig,
        interaction_script: Optional[str] = None,
        modify_requests: Optional[Callable[[APICall], APICall]] = None,
    ) -> BrowserResult:
        """
        Test Single Page Application with API call interception.
        
        Args:
            target: Target configuration
            interaction_script: Optional JavaScript to interact with SPA
            modify_requests: Optional function to modify intercepted requests
            
        Returns:
            BrowserResult with intercepted API calls
        """
        await self._ensure_browser()
        
        result = BrowserResult(url=target.url, success=False)
        
        try:
            # Create new page
            context = await self._browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # Set up API call interception
            api_calls = []
            
            async def handle_route(route, request):
                """Intercept and optionally modify API calls"""
                # Create APICall object
                api_call = APICall(
                    url=request.url,
                    method=request.method,
                    headers=request.headers,
                    request_body=request.post_data,
                    timestamp=asyncio.get_event_loop().time(),
                )
                
                # Modify request if function provided
                if modify_requests:
                    api_call = modify_requests(api_call)
                    
                    # Apply modifications
                    await route.continue_(
                        method=api_call.method,
                        headers=api_call.headers,
                        post_data=api_call.request_body,
                    )
                else:
                    await route.continue_()
                
                # Store API call
                api_calls.append(api_call)
            
            # Intercept API calls (common API patterns)
            await page.route("**/api/**", handle_route)
            await page.route("**/graphql**", handle_route)
            await page.route("**/v1/**", handle_route)
            await page.route("**/v2/**", handle_route)
            
            # Set up response capture
            page.on("response", lambda response: self._capture_response(response, api_calls))
            
            # Navigate to page
            await page.goto(target.url, wait_until="networkidle", timeout=30000)
            
            # Execute interaction script if provided
            if interaction_script:
                await page.evaluate(interaction_script)
                await asyncio.sleep(2.0)  # Wait for API calls
            else:
                # Default: wait for page to settle
                await asyncio.sleep(3.0)
            
            # Get rendered HTML
            rendered_html = await page.content()
            result.rendered_html = rendered_html
            
            # Store API calls
            result.api_calls = api_calls
            
            result.success = True
            result.metadata = {
                "api_calls_count": len(api_calls),
                "final_url": page.url,
            }
            
            await context.close()
        
        except Exception as e:
            result.error = f"Error testing SPA: {str(e)}"
        
        return result
    
    def _capture_response(self, response, api_calls: List[APICall]):
        """Capture response data for API calls"""
        try:
            # Find matching API call
            for api_call in api_calls:
                if api_call.url == response.url and api_call.response_status is None:
                    api_call.response_status = response.status
                    api_call.response_headers = response.headers
                    # Note: response.body() is async, we'll skip it for now
                    break
        except Exception:
            pass  # Non-critical
    
    async def test_clickjacking(
        self,
        target: TargetConfig,
        generate_poc: bool = True,
    ) -> ClickjackingResult:
        """
        Test for clickjacking vulnerabilities.
        
        Args:
            target: Target configuration
            generate_poc: Whether to generate visual PoC
            
        Returns:
            ClickjackingResult with vulnerability status
        """
        result = ClickjackingResult(
            is_vulnerable=False,
            frame_busting_present=False,
            frame_busting_bypassed=False,
        )
        
        try:
            # First, check headers
            response = await self.request_handler.send_request(
                method='GET',
                url=target.url,
                headers=target.custom_headers,
                proxy=target.proxy,
            )
            
            # Check X-Frame-Options header
            x_frame_options = response.headers.get('x-frame-options', '').lower()
            result.x_frame_options = x_frame_options if x_frame_options else None
            
            # Check CSP frame-ancestors
            csp = response.headers.get('content-security-policy', '').lower()
            if 'frame-ancestors' in csp:
                # Extract frame-ancestors directive
                match = None
                for directive in csp.split(';'):
                    if 'frame-ancestors' in directive:
                        match = directive.strip()
                        break
                result.csp_frame_ancestors = match
            
            # If no protection headers, likely vulnerable
            if not x_frame_options and not result.csp_frame_ancestors:
                result.is_vulnerable = True
                result.evidence.append("No X-Frame-Options or CSP frame-ancestors header present")
            
            # Now test with browser
            await self._ensure_browser()
            
            context = await self._browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # Create a test page that frames the target
            frame_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Clickjacking Test</title>
            </head>
            <body>
                <h1>Clickjacking Test</h1>
                <iframe id="target" src="{target.url}" width="800" height="600"></iframe>
                <script>
                    // Check if frame loaded
                    window.frameLoaded = false;
                    document.getElementById('target').onload = function() {{
                        window.frameLoaded = true;
                    }};
                    
                    // Check for frame-busting
                    window.frameBustingDetected = false;
                    if (window.top !== window.self) {{
                        window.frameBustingDetected = true;
                    }}
                </script>
            </body>
            </html>
            """
            
            # Set content and wait
            await page.set_content(frame_html)
            await asyncio.sleep(3.0)  # Wait for frame to load
            
            # Check if frame loaded successfully
            frame_loaded = await page.evaluate("window.frameLoaded")
            frame_busting_detected = await page.evaluate("window.frameBustingDetected")
            
            if frame_loaded:
                result.is_vulnerable = True
                result.evidence.append("Target successfully loaded in iframe")
                
                # Check for frame-busting in page content
                if 'top.location' in response.text or 'self.location' in response.text:
                    result.frame_busting_present = True
                    result.evidence.append("Frame-busting code detected in page")
                    
                    # But if frame still loaded, it was bypassed
                    result.frame_busting_bypassed = True
                    result.evidence.append("Frame-busting code was bypassed")
            else:
                result.evidence.append("Target could not be loaded in iframe")
                
                # Check if it's due to headers or frame-busting
                if x_frame_options or result.csp_frame_ancestors:
                    result.evidence.append("Blocked by security headers")
                else:
                    result.frame_busting_present = True
                    result.evidence.append("Blocked by frame-busting code")
            
            # Generate PoC if requested and vulnerable
            if generate_poc and result.is_vulnerable:
                result.poc_html = self._generate_clickjacking_poc(target.url)
            
            await context.close()
        
        except Exception as e:
            result.evidence.append(f"Error during clickjacking test: {str(e)}")
        
        return result
    
    def _generate_clickjacking_poc(self, target_url: str) -> str:
        """Generate visual clickjacking PoC"""
        poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
        
        .container {{
            position: relative;
            width: 800px;
            height: 600px;
            margin: 50px auto;
        }}
        
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 800px;
            height: 600px;
            opacity: 0.5; /* Set to 0 for real attack */
            z-index: 2;
        }}
        
        .decoy {{
            position: absolute;
            top: 0;
            left: 0;
            width: 800px;
            height: 600px;
            z-index: 1;
            background: white;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .button {{
            padding: 20px 40px;
            font-size: 24px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="decoy">
            <button class="button">Click here to win a prize!</button>
        </div>
        <iframe src="{target_url}"></iframe>
    </div>
    <p style="text-align: center; margin-top: 20px;">
        <strong>Note:</strong> This is a proof-of-concept. The iframe opacity is set to 0.5 for demonstration.
        In a real attack, it would be set to 0 (invisible).
    </p>
</body>
</html>"""
        
        return poc_html
    
    async def extract_client_storage(
        self,
        target: TargetConfig,
        storage_types: Optional[List[StorageType]] = None,
    ) -> List[StorageData]:
        """
        Extract data from client-side storage.
        
        Args:
            target: Target configuration
            storage_types: List of storage types to extract (default: all)
            
        Returns:
            List of StorageData objects
        """
        if storage_types is None:
            storage_types = list(StorageType)
        
        await self._ensure_browser()
        
        storage_data = []
        
        try:
            # Create new page
            context = await self._browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # Navigate to page
            await page.goto(target.url, wait_until="networkidle", timeout=30000)
            
            # Wait for page to settle
            await asyncio.sleep(2.0)
            
            # Extract storage based on types
            if StorageType.LOCAL_STORAGE in storage_types:
                local_storage = await self._extract_local_storage(page)
                storage_data.extend(local_storage)
            
            if StorageType.SESSION_STORAGE in storage_types:
                session_storage = await self._extract_session_storage(page)
                storage_data.extend(session_storage)
            
            if StorageType.INDEXED_DB in storage_types:
                indexed_db = await self._extract_indexed_db(page)
                storage_data.extend(indexed_db)
            
            if StorageType.COOKIES in storage_types:
                cookies = await context.cookies()
                for cookie in cookies:
                    storage_data.append(StorageData(
                        storage_type=StorageType.COOKIES,
                        key=cookie['name'],
                        value=cookie['value'],
                        domain=cookie.get('domain'),
                        metadata={
                            'path': cookie.get('path'),
                            'expires': cookie.get('expires'),
                            'httpOnly': cookie.get('httpOnly'),
                            'secure': cookie.get('secure'),
                            'sameSite': cookie.get('sameSite'),
                        }
                    ))
            
            await context.close()
        
        except Exception as e:
            # Return what we have so far
            pass
        
        return storage_data
    
    async def _extract_storage(self, page) -> List[StorageData]:
        """Extract all storage types from page"""
        storage_data = []
        
        try:
            # Extract localStorage
            local_storage = await self._extract_local_storage(page)
            storage_data.extend(local_storage)
            
            # Extract sessionStorage
            session_storage = await self._extract_session_storage(page)
            storage_data.extend(session_storage)
            
            # Extract IndexedDB
            indexed_db = await self._extract_indexed_db(page)
            storage_data.extend(indexed_db)
        
        except Exception:
            pass  # Non-critical
        
        return storage_data
    
    async def _extract_local_storage(self, page) -> List[StorageData]:
        """Extract localStorage data"""
        storage_data = []
        
        try:
            # Execute JavaScript to get localStorage
            local_storage_js = """
            () => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            }
            """
            
            items = await page.evaluate(local_storage_js)
            
            for key, value in items.items():
                storage_data.append(StorageData(
                    storage_type=StorageType.LOCAL_STORAGE,
                    key=key,
                    value=value,
                    domain=urlparse(page.url).netloc,
                ))
        
        except Exception:
            pass  # Non-critical
        
        return storage_data
    
    async def _extract_session_storage(self, page) -> List[StorageData]:
        """Extract sessionStorage data"""
        storage_data = []
        
        try:
            # Execute JavaScript to get sessionStorage
            session_storage_js = """
            () => {
                const items = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return items;
            }
            """
            
            items = await page.evaluate(session_storage_js)
            
            for key, value in items.items():
                storage_data.append(StorageData(
                    storage_type=StorageType.SESSION_STORAGE,
                    key=key,
                    value=value,
                    domain=urlparse(page.url).netloc,
                ))
        
        except Exception:
            pass  # Non-critical
        
        return storage_data
    
    async def _extract_indexed_db(self, page) -> List[StorageData]:
        """Extract IndexedDB data"""
        storage_data = []
        
        try:
            # Execute JavaScript to get IndexedDB
            indexed_db_js = """
            async () => {
                const databases = await indexedDB.databases();
                const result = [];
                
                for (const dbInfo of databases) {
                    const dbName = dbInfo.name;
                    
                    // Open database
                    const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open(dbName);
                        request.onsuccess = () => resolve(request.result);
                        request.onerror = () => reject(request.error);
                    });
                    
                    // Get all object stores
                    const objectStoreNames = Array.from(db.objectStoreNames);
                    
                    for (const storeName of objectStoreNames) {
                        // Get all data from object store
                        const transaction = db.transaction(storeName, 'readonly');
                        const objectStore = transaction.objectStore(storeName);
                        
                        const data = await new Promise((resolve, reject) => {
                            const request = objectStore.getAll();
                            request.onsuccess = () => resolve(request.result);
                            request.onerror = () => reject(request.error);
                        });
                        
                        result.push({
                            database: dbName,
                            objectStore: storeName,
                            data: data
                        });
                    }
                    
                    db.close();
                }
                
                return result;
            }
            """
            
            indexed_db_data = await page.evaluate(indexed_db_js)
            
            for db_entry in indexed_db_data:
                storage_data.append(StorageData(
                    storage_type=StorageType.INDEXED_DB,
                    key=f"{db_entry['database']}.{db_entry['objectStore']}",
                    value=db_entry['data'],
                    domain=urlparse(page.url).netloc,
                    metadata={
                        'database': db_entry['database'],
                        'objectStore': db_entry['objectStore'],
                    }
                ))
        
        except Exception:
            pass  # Non-critical, IndexedDB might not be used
        
        return storage_data
