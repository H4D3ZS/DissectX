"""Out-of-Band (OOB) Listener for HTTP and DNS callbacks

This module implements an OOB listener that captures HTTP and DNS callbacks
from exploited targets, enabling detection of blind vulnerabilities.
"""

import asyncio
import uuid
import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, AsyncIterator
from urllib.parse import unquote, unquote_plus
import logging

from aiohttp import web
import dnslib
from dnslib.server import DNSServer, BaseResolver

from src.vulnchain.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class Callback:
    """Represents an OOB callback received from a target"""

    callback_id: str
    unique_id: str
    callback_type: str  # 'http' or 'dns'
    source_ip: str
    timestamp: datetime
    data: Dict = field(default_factory=dict)
    decoded_data: Optional[str] = None


@dataclass
class PayloadRegistration:
    """Represents a registered payload for correlation"""

    unique_id: str
    payload: str
    target_url: str
    injection_point: str
    vulnerability_type: str
    timestamp: datetime
    metadata: Dict = field(default_factory=dict)


class OOBResolver(BaseResolver):
    """Custom DNS resolver that logs all queries"""

    def __init__(self, oob_listener: "OOBListener"):
        self.oob_listener = oob_listener

    def resolve(self, request, handler):
        """Resolve DNS query and log the callback"""
        reply = request.reply()
        qname = str(request.q.qname)

        # Extract source IP from handler
        source_ip = handler.client_address[0] if handler.client_address else "unknown"

        # Log the DNS query
        logger.info(f"DNS query received: {qname} from {source_ip}")

        # Extract unique ID from subdomain if present
        unique_id = self._extract_unique_id(qname)

        # Create callback record
        callback = Callback(
            callback_id=str(uuid.uuid4()),
            unique_id=unique_id or "unknown",
            callback_type="dns",
            source_ip=source_ip,
            timestamp=datetime.now(timezone.utc),
            data={
                "query": qname,
                "query_type": str(request.q.qtype),
            },
        )

        # Store the callback
        asyncio.create_task(self.oob_listener._store_callback(callback))

        # Return a dummy A record
        reply.add_answer(
            dnslib.RR(
                request.q.qname,
                dnslib.QTYPE.A,
                rdata=dnslib.A("127.0.0.1"),
                ttl=60,
            )
        )

        return reply

    def _extract_unique_id(self, qname: str) -> Optional[str]:
        """Extract unique identifier from DNS query name"""
        # Expected format: <unique_id>.<domain>
        parts = qname.rstrip(".").split(".")
        if len(parts) >= 2:
            # First part is the unique ID
            return parts[0]
        return None


class OOBListener:
    """Out-of-Band listener for HTTP and DNS callbacks"""

    def __init__(
        self,
        http_port: int = None,
        dns_port: int = None,
        domain: str = None,
    ):
        """Initialize OOB listener

        Args:
            http_port: Port for HTTP listener (default from settings)
            dns_port: Port for DNS listener (default from settings)
            domain: Domain for OOB callbacks (default from settings)
        """
        self.http_port = http_port or settings.OOB_HTTP_PORT
        self.dns_port = dns_port or settings.OOB_DNS_PORT
        self.domain = domain or settings.OOB_DOMAIN

        self.callbacks: Dict[str, List[Callback]] = {}
        self.payloads: Dict[str, PayloadRegistration] = {}
        self._callbacks_lock = asyncio.Lock()
        self._payloads_lock = asyncio.Lock()
        self._running = False
        self._http_runner: Optional[web.AppRunner] = None
        self._dns_server: Optional[DNSServer] = None
        self._waiters: Dict[str, List[asyncio.Future]] = {}

        logger.info(
            f"OOB Listener initialized: HTTP port {self.http_port}, "
            f"DNS port {self.dns_port}, domain {self.domain}"
        )

    async def start(self):
        """Start HTTP and DNS listeners"""
        if self._running:
            logger.warning("OOB Listener already running")
            return

        logger.info("Starting OOB Listener...")

        # Start HTTP listener
        await self._start_http_listener()

        # Start DNS listener
        await self._start_dns_listener()

        self._running = True
        logger.info("OOB Listener started successfully")

    async def stop(self):
        """Stop HTTP and DNS listeners"""
        if not self._running:
            return

        logger.info("Stopping OOB Listener...")

        # Stop HTTP listener
        if self._http_runner:
            await self._http_runner.cleanup()
            self._http_runner = None

        # Stop DNS listener
        if self._dns_server:
            self._dns_server.stop()
            self._dns_server = None

        self._running = False
        logger.info("OOB Listener stopped")

    async def _start_http_listener(self):
        """Start HTTP listener for callbacks"""
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle_http_callback)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "0.0.0.0", self.http_port)
        await site.start()

        self._http_runner = runner
        logger.info(f"HTTP listener started on port {self.http_port}")

    async def _start_dns_listener(self):
        """Start DNS listener for callbacks"""
        try:
            resolver = OOBResolver(self)
            self._dns_server = DNSServer(
                resolver,
                port=self.dns_port,
                address="0.0.0.0",
            )
            self._dns_server.start_thread()
            logger.info(f"DNS listener started on port {self.dns_port}")
        except Exception as e:
            logger.error(f"Failed to start DNS listener: {e}")
            logger.warning("DNS listener requires root/admin privileges on port 53")

    async def _handle_http_callback(self, request: web.Request) -> web.Response:
        """Handle incoming HTTP callback"""
        # Extract information from request
        source_ip = request.remote or "unknown"
        path = request.path
        method = request.method
        headers = dict(request.headers)
        query_params = dict(request.query)

        # Try to read body
        try:
            body = await request.text()
        except Exception:
            body = ""

        logger.info(f"HTTP callback received: {method} {path} from {source_ip}")

        # Extract unique ID from path or query params
        unique_id = self._extract_unique_id_from_http(path, query_params)

        # Create callback record
        callback = Callback(
            callback_id=str(uuid.uuid4()),
            unique_id=unique_id or "unknown",
            callback_type="http",
            source_ip=source_ip,
            timestamp=datetime.now(timezone.utc),
            data={
                "method": method,
                "path": path,
                "headers": headers,
                "query_params": query_params,
                "body": body,
            },
        )

        # Store the callback
        await self._store_callback(callback)

        # Return success response
        return web.Response(text="OK", status=200)

    def _extract_unique_id_from_http(
        self, path: str, query_params: Dict
    ) -> Optional[str]:
        """Extract unique identifier from HTTP request"""
        # Check query parameter
        if "id" in query_params:
            return query_params["id"]

        # Check path (format: /<unique_id>/...)
        parts = path.strip("/").split("/")
        if parts and parts[0]:
            return parts[0]

        return None

    async def _store_callback(self, callback: Callback):
        """Store callback and notify waiters"""
        # Attempt to decode exfiltrated data
        callback.decoded_data = self._decode_exfiltrated_data(callback)

        async with self._callbacks_lock:
            # Store by unique ID
            if callback.unique_id not in self.callbacks:
                self.callbacks[callback.unique_id] = []
            self.callbacks[callback.unique_id].append(callback)

            # Also store under "all" for general queries
            if "all" not in self.callbacks:
                self.callbacks["all"] = []
            self.callbacks["all"].append(callback)

            logger.info(
                f"Callback stored: {callback.callback_type} from {callback.source_ip} "
                f"(unique_id: {callback.unique_id})"
            )
            if callback.decoded_data:
                logger.info(f"Decoded data: {callback.decoded_data[:100]}...")

        # Notify waiters
        if callback.unique_id in self._waiters:
            for future in self._waiters[callback.unique_id]:
                if not future.done():
                    future.set_result(callback)
            del self._waiters[callback.unique_id]

    def _decode_exfiltrated_data(self, callback: Callback) -> Optional[str]:
        """Attempt to decode exfiltrated data from callback

        Tries multiple decoding schemes:
        - URL encoding
        - Base64
        - Hex encoding
        - Double encoding combinations

        Args:
            callback: The callback containing potential encoded data

        Returns:
            Decoded string if successful, None otherwise
        """
        # Extract potential encoded data from callback
        encoded_data = self._extract_encoded_data(callback)
        if not encoded_data:
            return None

        # Try different decoding schemes in order of likelihood
        decoders = [
            ("url", self._decode_url),
            ("base64", self._decode_base64),
            ("hex", self._decode_hex),
            ("url+base64", lambda d: self._decode_base64(self._decode_url(d))),
            ("base64+url", lambda d: self._decode_url(self._decode_base64(d))),
        ]

        best_decoded = encoded_data
        best_score = 0

        for scheme_name, decoder in decoders:
            try:
                decoded = decoder(encoded_data)
                if decoded and decoded != encoded_data:
                    # Score the decoded result
                    score = self._score_decoded(decoded)
                    if score > best_score:
                        best_decoded = decoded
                        best_score = score
                        logger.info(f"Decoded using {scheme_name} (score: {score})")
            except Exception as e:
                logger.debug(f"Failed to decode with {scheme_name}: {e}")
                continue

        return best_decoded

    def _score_decoded(self, data: str) -> float:
        """Score decoded data based on how valid it looks

        Args:
            data: Decoded string to score

        Returns:
            Score from 0.0 to 1.0
        """
        if not data:
            return 0.0

        # Count printable characters
        printable_count = sum(1 for c in data if c.isprintable() or c.isspace())
        printable_ratio = printable_count / len(data)

        # Count alphanumeric characters
        alnum_count = sum(1 for c in data if c.isalnum() or c.isspace())
        alnum_ratio = alnum_count / len(data)

        # Combine scores (weighted average)
        score = (printable_ratio * 0.6) + (alnum_ratio * 0.4)

        return score



    def _extract_encoded_data(self, callback: Callback) -> Optional[str]:
        """Extract potential encoded data from callback

        Args:
            callback: The callback to extract data from

        Returns:
            Extracted data string or None
        """
        if callback.callback_type == "dns":
            # For DNS, extract from query name
            query = callback.data.get("query", "")
            # Remove domain suffix and unique ID
            parts = query.rstrip(".").split(".")
            if len(parts) > 2:
                # Data might be in subdomain parts after unique ID
                return ".".join(parts[1:-2]) if len(parts) > 2 else None
            return None

        elif callback.callback_type == "http":
            # For HTTP, check multiple locations
            # 1. Query parameters
            query_params = callback.data.get("query_params", {})
            if "data" in query_params:
                return query_params["data"]

            # 2. Path segments (after unique ID)
            path = callback.data.get("path", "")
            parts = path.strip("/").split("/")
            if len(parts) > 1:
                return "/".join(parts[1:])

            # 3. Body
            body = callback.data.get("body", "")
            if body:
                return body

        return None

    def _decode_base64(self, data: str) -> Optional[str]:
        """Decode base64 encoded data

        Args:
            data: Base64 encoded string

        Returns:
            Decoded string or None
        """
        if not data:
            return None

        try:
            # Try standard base64
            decoded_bytes = base64.b64decode(data)
            return decoded_bytes.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            try:
                # Try URL-safe base64
                decoded_bytes = base64.urlsafe_b64decode(data + "==")
                return decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                return None

    def _decode_url(self, data: str) -> Optional[str]:
        """Decode URL encoded data

        Args:
            data: URL encoded string

        Returns:
            Decoded string or None
        """
        if not data:
            return None

        try:
            # Check if data contains URL encoding patterns
            if "%" in data or "+" in data:
                # Try standard URL decoding
                decoded = unquote(data)
                if decoded != data:
                    return decoded

                # Try plus-to-space URL decoding
                decoded = unquote_plus(data)
                if decoded != data:
                    return decoded

            return data
        except Exception:
            return None

    def _decode_hex(self, data: str) -> Optional[str]:
        """Decode hex encoded data

        Args:
            data: Hex encoded string

        Returns:
            Decoded string or None
        """
        if not data:
            return None

        try:
            # Remove common hex prefixes
            clean_data = data.replace("0x", "").replace("\\x", "")

            # Try to decode as hex
            decoded_bytes = bytes.fromhex(clean_data)
            return decoded_bytes.decode("utf-8", errors="ignore")
        except (ValueError, AttributeError):
            return None

    def generate_unique_id(self) -> str:
        """Generate unique identifier for payload correlation

        Returns:
            Unique identifier string
        """
        return str(uuid.uuid4())

    def get_callback_url(self, unique_id: str) -> str:
        """Get callback URL with unique identifier

        Args:
            unique_id: Unique identifier for correlation

        Returns:
            Full callback URL
        """
        return f"http://{self.domain}:{self.http_port}/{unique_id}"

    def get_dns_callback(self, unique_id: str) -> str:
        """Get DNS callback hostname with unique identifier

        Args:
            unique_id: Unique identifier for correlation

        Returns:
            DNS hostname for callback
        """
        return f"{unique_id}.{self.domain}"

    async def wait_for_callback(
        self, unique_id: str, timeout: float = 30.0
    ) -> Optional[Callback]:
        """Wait for callback with timeout

        Args:
            unique_id: Unique identifier to wait for
            timeout: Timeout in seconds

        Returns:
            Callback if received, None if timeout
        """
        # Check if callback already exists
        async with self._callbacks_lock:
            if unique_id in self.callbacks and self.callbacks[unique_id]:
                return self.callbacks[unique_id][-1]

        # Create future for waiting
        future = asyncio.Future()
        if unique_id not in self._waiters:
            self._waiters[unique_id] = []
        self._waiters[unique_id].append(future)

        try:
            # Wait with timeout
            callback = await asyncio.wait_for(future, timeout=timeout)
            return callback
        except asyncio.TimeoutError:
            logger.debug(f"Timeout waiting for callback: {unique_id}")
            return None
        finally:
            # Clean up waiter
            if unique_id in self._waiters:
                try:
                    self._waiters[unique_id].remove(future)
                    if not self._waiters[unique_id]:
                        del self._waiters[unique_id]
                except ValueError:
                    pass

    def get_callbacks(self, unique_id: Optional[str] = None) -> List[Callback]:
        """Retrieve captured callbacks

        Args:
            unique_id: Optional unique identifier to filter by

        Returns:
            List of callbacks
        """
        if unique_id:
            return self.callbacks.get(unique_id, [])
        return self.callbacks.get("all", [])

    async def stream_callbacks(self) -> AsyncIterator[Callback]:
        """Stream callbacks in real-time

        Yields:
            Callbacks as they are received
        """
        last_count = 0
        while True:
            all_callbacks = self.get_callbacks()
            if len(all_callbacks) > last_count:
                # Yield new callbacks
                for callback in all_callbacks[last_count:]:
                    yield callback
                last_count = len(all_callbacks)
            await asyncio.sleep(0.1)

    def clear_callbacks(self, unique_id: Optional[str] = None):
        """Clear stored callbacks

        Args:
            unique_id: Optional unique identifier to clear specific callbacks
        """
        if unique_id:
            if unique_id in self.callbacks:
                del self.callbacks[unique_id]
                logger.info(f"Cleared callbacks for unique_id: {unique_id}")
        else:
            self.callbacks.clear()
            logger.info("Cleared all callbacks")

    async def register_payload(
        self,
        unique_id: str,
        payload: str,
        target_url: str,
        injection_point: str,
        vulnerability_type: str,
        metadata: Optional[Dict] = None,
    ):
        """Register a payload for correlation with callbacks

        Args:
            unique_id: Unique identifier for this payload
            payload: The actual payload sent
            target_url: Target URL where payload was sent
            injection_point: Parameter or location where payload was injected
            vulnerability_type: Type of vulnerability being tested
            metadata: Additional metadata
        """
        async with self._payloads_lock:
            registration = PayloadRegistration(
                unique_id=unique_id,
                payload=payload,
                target_url=target_url,
                injection_point=injection_point,
                vulnerability_type=vulnerability_type,
                timestamp=datetime.now(timezone.utc),
                metadata=metadata or {},
            )
            self.payloads[unique_id] = registration
            logger.info(
                f"Registered payload: {vulnerability_type} at {target_url} "
                f"(unique_id: {unique_id})"
            )

    def get_payload_registration(
        self, unique_id: str
    ) -> Optional[PayloadRegistration]:
        """Get payload registration by unique ID

        Args:
            unique_id: Unique identifier

        Returns:
            PayloadRegistration if found, None otherwise
        """
        return self.payloads.get(unique_id)

    def correlate_callback(self, callback: Callback) -> Optional[PayloadRegistration]:
        """Correlate a callback with its originating payload

        Args:
            callback: The callback to correlate

        Returns:
            PayloadRegistration if correlation found, None otherwise
        """
        return self.get_payload_registration(callback.unique_id)

    def get_correlated_callbacks(
        self, unique_id: str
    ) -> tuple[Optional[PayloadRegistration], List[Callback]]:
        """Get payload registration and all its callbacks

        Args:
            unique_id: Unique identifier

        Returns:
            Tuple of (PayloadRegistration, List[Callback])
        """
        payload = self.get_payload_registration(unique_id)
        callbacks = self.get_callbacks(unique_id)
        return payload, callbacks

    def get_all_correlations(self) -> List[tuple[PayloadRegistration, List[Callback]]]:
        """Get all payload-callback correlations

        Returns:
            List of tuples (PayloadRegistration, List[Callback])
        """
        correlations = []
        for unique_id, payload in self.payloads.items():
            callbacks = self.get_callbacks(unique_id)
            correlations.append((payload, callbacks))
        return correlations

    @property
    def is_running(self) -> bool:
        """Check if listener is running"""
        return self._running
