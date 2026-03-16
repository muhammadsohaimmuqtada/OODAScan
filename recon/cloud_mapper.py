"""
recon/cloud_mapper.py
---------------------
Asynchronous cloud asset reconnaissance module.

Generates target-specific environment/role permutations and checks for
publicly exposed storage buckets on:
  - Amazon Web Services (S3)
  - Google Cloud Platform (GCS)
  - Microsoft Azure (Blob Storage)

All detection is based on native HTTP response analysis — no cloud-provider
SDK or third-party API is required.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

import aiohttp

from utils.evasion import EvasionEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Permutation templates
# ---------------------------------------------------------------------------

_ENV_SUFFIXES: List[str] = [
    "", "-dev", "-development", "-staging", "-stage", "-stg",
    "-prod", "-production", "-test", "-qa", "-uat",
    "-backup", "-bak", "-old", "-new", "-v2",
    "-internal", "-private", "-public", "-data", "-assets",
    "-media", "-static", "-uploads", "-files", "-images",
    "-logs", "-archive", "-config", "-secrets",
]

_SEPARATORS: List[str] = ["-", ".", "_", ""]

# ---------------------------------------------------------------------------
# Detector signatures
# ---------------------------------------------------------------------------

# AWS S3
_S3_INDICATORS = {
    "open": ["ListBucketResult", "<Key>"],
    "exists_but_denied": ["AccessDenied", "AllAccessDisabled", "NoSuchBucket"],
}

# GCS
_GCS_INDICATORS = {
    "open": ['"kind": "storage#objects"', '"items":'],
    "exists_but_denied": ["AccessDenied", "Forbidden", "NoSuchBucket"],
}

# Azure Blob
_AZURE_INDICATORS = {
    "open": ["<EnumerationResults", "<Blobs>"],
    "exists_but_denied": ["AuthenticationFailed", "PublicAccessNotPermitted",
                          "ResourceNotFound"],
}

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class BucketFinding:
    """Represents a discovered (or probed) cloud storage asset."""
    provider: str          # "aws", "gcp", "azure"
    bucket_name: str
    url: str
    status: str            # "OPEN", "EXISTS_PROTECTED", "NOT_FOUND"
    http_status: int
    details: str = ""


# ---------------------------------------------------------------------------
# Cloud mapper
# ---------------------------------------------------------------------------

class CloudMapper:
    """
    Async scanner that hunts for misconfigured cloud storage buckets.

    Parameters
    ----------
    concurrency:
        Maximum number of simultaneous HTTP requests.
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(self, concurrency: int = 30, timeout: float = 8.0) -> None:
        self._concurrency = concurrency
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._evasion = EvasionEngine()
        self._findings: List[BucketFinding] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, target: str) -> List[BucketFinding]:
        """
        Generate all bucket name permutations from *target* and probe
        all three cloud providers asynchronously.

        Parameters
        ----------
        target:
            Base target name (e.g. "acme" or "acme.com").
        """
        self._findings = []
        base = self._normalise_base(target)
        names = self._generate_permutations(base)

        logger.info(
            "CloudMapper: probing %d bucket name permutations for '%s'",
            len(names), base,
        )

        connector = aiohttp.TCPConnector(limit=self._concurrency, ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            tasks = []
            for name in names:
                tasks.append(asyncio.create_task(self._probe_aws(session, name)))
                tasks.append(asyncio.create_task(self._probe_gcp(session, name)))
                tasks.append(asyncio.create_task(self._probe_azure(session, name)))
            await asyncio.gather(*tasks, return_exceptions=True)

        open_count = sum(1 for f in self._findings if f.status == "OPEN")
        logger.info(
            "CloudMapper: %d findings (%d OPEN) for '%s'",
            len(self._findings), open_count, base,
        )
        return self._findings

    # ------------------------------------------------------------------
    # Permutation generator
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_base(target: str) -> str:
        """Strip scheme, www prefix, and TLD from target."""
        stripped = re.sub(r"^https?://", "", target)
        stripped = re.sub(r"^www\.", "", stripped)
        # Remove TLD (everything after the last dot if it looks like a TLD)
        parts = stripped.split(".")
        if len(parts) >= 2 and len(parts[-1]) <= 4:
            stripped = ".".join(parts[:-1])
        return stripped.rstrip("/")

    @staticmethod
    def _generate_permutations(base: str) -> List[str]:
        names: Set[str] = set()
        for sep in _SEPARATORS:
            for suffix in _ENV_SUFFIXES:
                candidate = f"{base}{sep}{suffix}".strip("-_.")
                if candidate:
                    names.add(candidate)
        return sorted(names)

    # ------------------------------------------------------------------
    # Provider-specific probes
    # ------------------------------------------------------------------

    async def _probe_aws(
        self, session: aiohttp.ClientSession, bucket_name: str
    ) -> None:
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        await self._probe(session, "aws", bucket_name, url, _S3_INDICATORS)

    async def _probe_gcp(
        self, session: aiohttp.ClientSession, bucket_name: str
    ) -> None:
        url = f"https://storage.googleapis.com/{bucket_name}/"
        await self._probe(session, "gcp", bucket_name, url, _GCS_INDICATORS)

    async def _probe_azure(
        self, session: aiohttp.ClientSession, bucket_name: str
    ) -> None:
        # Azure storage account names must be 3-24 chars, lowercase alphanumeric
        safe_name = re.sub(r"[^a-z0-9]", "", bucket_name.lower())[:24]
        if len(safe_name) < 3:
            return
        url = f"https://{safe_name}.blob.core.windows.net/?comp=list"
        await self._probe(session, "azure", safe_name, url, _AZURE_INDICATORS)

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        provider: str,
        bucket_name: str,
        url: str,
        indicators: Dict[str, List[str]],
    ) -> None:
        headers = self._evasion.build_headers()
        try:
            async with session.get(url, headers=headers) as resp:
                body = await resp.text()
                http_status = resp.status
        except aiohttp.ClientConnectorError:
            return  # DNS NXDOMAIN — bucket does not exist
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("Probe error [%s] %s: %s", provider, url, exc)
            return

        status, details = self._classify(http_status, body, indicators)
        if status == "NOT_FOUND":
            return  # Reduce noise

        finding = BucketFinding(
            provider=provider,
            bucket_name=bucket_name,
            url=url,
            status=status,
            http_status=http_status,
            details=details,
        )
        self._findings.append(finding)
        log_fn = logger.warning if status == "OPEN" else logger.info
        log_fn(
            "[CloudMapper] %s %s bucket '%s': %s (HTTP %d)",
            status, provider.upper(), bucket_name, details, http_status,
        )

    @staticmethod
    def _classify(
        http_status: int,
        body: str,
        indicators: Dict[str, List[str]],
    ) -> Tuple[str, str]:
        for sig in indicators.get("open", []):
            if sig in body:
                return "OPEN", f"Bucket is publicly listable (matched '{sig}')"

        for sig in indicators.get("exists_but_denied", []):
            if sig in body:
                if "NoSuchBucket" in sig or "ResourceNotFound" in sig:
                    return "NOT_FOUND", "Bucket does not exist"
                return "EXISTS_PROTECTED", f"Bucket exists but access denied (matched '{sig}')"

        if http_status == 200:
            return "OPEN", "HTTP 200 with no recognised listing signature"
        if http_status == 403:
            return "EXISTS_PROTECTED", "HTTP 403 — bucket exists but access is denied"
        if http_status == 404:
            return "NOT_FOUND", "HTTP 404 — bucket not found"

        return "NOT_FOUND", f"Unrecognised HTTP {http_status}"
