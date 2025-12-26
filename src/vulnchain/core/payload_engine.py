"""Payload Engine for wordlist management, encoding, and mutation"""

import base64
import html
import random
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set


class EncodingType(Enum):
    """Supported encoding types"""

    URL = "url"
    DOUBLE_URL = "double_url"
    HTML_ENTITY = "html_entity"
    BASE64 = "base64"
    UNICODE = "unicode"
    HEX = "hex"
    CASE_VARIATION = "case_variation"


class MutationStrategy(Enum):
    """Mutation strategies for payload generation"""

    ENCODING_VARIATION = "encoding_variation"
    CASE_VARIATION = "case_variation"
    SYNTAX_VARIATION = "syntax_variation"
    GENETIC = "genetic"


@dataclass
class Payload:
    """Payload representation"""

    original: str
    encoded: str
    category: str
    encoding_chain: List[str] = field(default_factory=list)
    metadata: Dict[str, any] = field(default_factory=dict)


class PayloadEngine:
    """
    Centralized payload management with encoding and mutation capabilities.

    Handles:
    - Loading and parsing wordlists from files
    - Storing payloads in memory with categorization
    - Payload iteration and delivery
    - Encoding (URL, HTML, Base64, Unicode, Hex)
    - Payload mutation and fuzzing
    """

    def __init__(self):
        """Initialize the Payload Engine"""
        self._payloads: Dict[str, List[str]] = {}
        self._custom_payloads: Dict[str, List[str]] = {}

    def load_wordlist(self, path: str, category: str) -> int:
        """
        Load wordlist from file into memory.

        Args:
            path: Path to wordlist file
            category: Category name for organizing payloads

        Returns:
            Number of payloads loaded

        Raises:
            FileNotFoundError: If wordlist file doesn't exist
            ValueError: If file is empty or invalid
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {path}")

        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {path}")

        payloads = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # Skip empty lines and comments
                    payloads.append(line)

        if not payloads:
            raise ValueError(f"Wordlist file is empty: {path}")

        if category not in self._payloads:
            self._payloads[category] = []

        self._payloads[category].extend(payloads)
        return len(payloads)

    def add_custom_payload(self, payload: str, category: str) -> None:
        """
        Add a custom payload to a category.

        Args:
            payload: Payload string
            category: Category name
        """
        if category not in self._custom_payloads:
            self._custom_payloads[category] = []

        self._custom_payloads[category].append(payload)

    def get_payloads(
        self,
        category: str,
        encoding: Optional[List[str]] = None,
        filters: Optional[Dict[str, any]] = None,
    ) -> Iterator[Payload]:
        """
        Get payloads with optional encoding.

        Args:
            category: Category name
            encoding: List of encoding types to apply (in order)
            filters: Optional filters (e.g., max_length, contains, regex)

        Yields:
            Payload objects with original and encoded versions
        """
        # Combine regular and custom payloads
        all_payloads = []
        if category in self._payloads:
            all_payloads.extend(self._payloads[category])
        if category in self._custom_payloads:
            all_payloads.extend(self._custom_payloads[category])

        if not all_payloads:
            return

        # Apply filters
        if filters:
            all_payloads = self._apply_filters(all_payloads, filters)

        # Generate payloads with encoding
        for payload_str in all_payloads:
            if encoding:
                encoded = self._apply_encoding_chain(payload_str, encoding)
                yield Payload(
                    original=payload_str,
                    encoded=encoded,
                    category=category,
                    encoding_chain=encoding,
                )
            else:
                yield Payload(
                    original=payload_str,
                    encoded=payload_str,
                    category=category,
                )

    def encode_payload(self, payload: str, encoding: str) -> str:
        """
        Apply single encoding to payload.

        Args:
            payload: Payload string
            encoding: Encoding type (url, html_entity, base64, unicode, hex)

        Returns:
            Encoded payload string
        """
        encoding_lower = encoding.lower()

        if encoding_lower == "url":
            return urllib.parse.quote(payload, safe="")
        elif encoding_lower == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif encoding_lower == "html_entity":
            return html.escape(payload)
        elif encoding_lower == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_lower == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding_lower == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding_lower == "case_variation":
            return self._random_case_variation(payload)
        else:
            raise ValueError(f"Unsupported encoding type: {encoding}")

    def mutate_payload(
        self, payload: str, strategy: MutationStrategy, count: int = 10
    ) -> List[str]:
        """
        Generate payload mutations.

        Args:
            payload: Original payload
            strategy: Mutation strategy
            count: Number of mutations to generate

        Returns:
            List of mutated payloads
        """
        if strategy == MutationStrategy.ENCODING_VARIATION:
            return self._mutate_encoding(payload, count)
        elif strategy == MutationStrategy.CASE_VARIATION:
            return self._mutate_case(payload, count)
        elif strategy == MutationStrategy.SYNTAX_VARIATION:
            return self._mutate_syntax(payload, count)
        elif strategy == MutationStrategy.GENETIC:
            return self._mutate_genetic(payload, count)
        else:
            raise ValueError(f"Unsupported mutation strategy: {strategy}")

    def get_categories(self) -> List[str]:
        """
        Get all available payload categories.

        Returns:
            List of category names
        """
        categories = set(self._payloads.keys()) | set(self._custom_payloads.keys())
        return sorted(list(categories))

    def get_payload_count(self, category: str) -> int:
        """
        Get number of payloads in a category.

        Args:
            category: Category name

        Returns:
            Number of payloads
        """
        count = 0
        if category in self._payloads:
            count += len(self._payloads[category])
        if category in self._custom_payloads:
            count += len(self._custom_payloads[category])
        return count

    def clear_category(self, category: str) -> None:
        """
        Clear all payloads from a category.

        Args:
            category: Category name
        """
        if category in self._payloads:
            del self._payloads[category]
        if category in self._custom_payloads:
            del self._custom_payloads[category]

    # Private helper methods

    def _apply_encoding_chain(self, payload: str, encodings: List[str]) -> str:
        """Apply multiple encodings in sequence"""
        result = payload
        for encoding in encodings:
            result = self.encode_payload(result, encoding)
        return result

    def _apply_filters(
        self, payloads: List[str], filters: Dict[str, any]
    ) -> List[str]:
        """Apply filters to payload list"""
        filtered = payloads

        if "max_length" in filters:
            max_len = filters["max_length"]
            filtered = [p for p in filtered if len(p) <= max_len]

        if "min_length" in filters:
            min_len = filters["min_length"]
            filtered = [p for p in filtered if len(p) >= min_len]

        if "contains" in filters:
            contains = filters["contains"]
            filtered = [p for p in filtered if contains in p]

        if "regex" in filters:
            pattern = re.compile(filters["regex"])
            filtered = [p for p in filtered if pattern.search(p)]

        return filtered

    def _random_case_variation(self, payload: str) -> str:
        """Generate random case variation"""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in payload
        )

    def _mutate_encoding(self, payload: str, count: int) -> List[str]:
        """Generate mutations with different encodings"""
        mutations = []
        encodings = ["url", "double_url", "html_entity", "base64", "unicode", "hex"]

        # Single encodings
        for encoding in encodings:
            try:
                mutations.append(self.encode_payload(payload, encoding))
            except Exception:
                pass

        # Double encodings
        for enc1 in encodings[:3]:  # Limit combinations
            for enc2 in encodings[:3]:
                if len(mutations) >= count:
                    break
                try:
                    encoded = self.encode_payload(payload, enc1)
                    encoded = self.encode_payload(encoded, enc2)
                    mutations.append(encoded)
                except Exception:
                    pass

        return mutations[:count]

    def _mutate_case(self, payload: str, count: int) -> List[str]:
        """Generate case variations"""
        mutations = [
            payload.lower(),
            payload.upper(),
            payload.capitalize(),
            payload.title(),
        ]

        # Random case variations
        for _ in range(count - len(mutations)):
            mutations.append(self._random_case_variation(payload))

        return mutations[:count]

    def _mutate_syntax(self, payload: str, count: int) -> List[str]:
        """Generate syntax variations (comments, whitespace, etc.)"""
        mutations = []

        # Add whitespace variations
        mutations.append(payload.replace(" ", "\t"))
        mutations.append(payload.replace(" ", "\n"))
        mutations.append(payload.replace(" ", "/**/"))

        # Add comment injections for SQL/code payloads
        if any(keyword in payload.lower() for keyword in ["select", "union", "or", "and"]):
            mutations.append(payload.replace(" ", "/**/"))
            mutations.append(payload.replace(" ", "--\n"))
            mutations.append(payload.replace("=", "/**/=/**/"))

        # Add null byte variations
        mutations.append(payload + "\x00")
        mutations.append(payload + "%00")

        # Pad to count
        while len(mutations) < count:
            mutations.append(payload + " " * random.randint(1, 5))

        return mutations[:count]

    def _mutate_genetic(self, payload: str, count: int) -> List[str]:
        """
        Generate mutations using genetic algorithm approach.
        Combines multiple mutation strategies.
        """
        mutations = []

        # Start with base mutations
        mutations.extend(self._mutate_case(payload, count // 3))
        mutations.extend(self._mutate_syntax(payload, count // 3))
        mutations.extend(self._mutate_encoding(payload, count // 3))

        # Generate hybrid mutations
        for _ in range(count - len(mutations)):
            # Randomly combine strategies
            mutated = payload
            strategies = random.sample(
                [
                    lambda p: self._random_case_variation(p),
                    lambda p: p.replace(" ", "/**/"),
                    lambda p: self.encode_payload(p, random.choice(["url", "hex"])),
                ],
                k=random.randint(1, 2),
            )

            for strategy in strategies:
                try:
                    mutated = strategy(mutated)
                except Exception:
                    pass

            mutations.append(mutated)

        return mutations[:count]
