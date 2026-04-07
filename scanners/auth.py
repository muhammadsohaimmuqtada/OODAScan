"""
scanners/auth.py
----------------
Authentication & authorisation vulnerability scanner.

Capabilities:
  - Offline JWT analysis:
      • `none` algorithm acceptance
      • Signature stripping
      • Weak-secret brute-force using a built-in wordlist
  - OAuth 2.0 state parameter validation
  - PKCE (Proof Key for Code Exchange) enforcement checks
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from utils.evasion import EvasionEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weak-secret wordlist (internal, no external API)
# ---------------------------------------------------------------------------

_WEAK_SECRETS: List[str] = [
    "secret", "password", "123456", "changeme", "qwerty",
    "admin", "letmein", "welcome", "monkey", "dragon",
    "jwt_secret", "your-256-bit-secret", "supersecret",
    "test", "dev", "development", "staging", "production",
    "key", "mykey", "privatekey", "app_secret", "flask_secret",
    "", "null", "undefined", "none",
]

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class JWTFinding:
    """Result of a JWT analysis."""
    issue: str
    token_preview: str
    details: str
    severity: str = "High"
    cracked_secret: Optional[str] = None


@dataclass
class OAuthFinding:
    """Result of an OAuth / PKCE check."""
    issue: str
    url: str
    details: str
    severity: str = "High"


# ---------------------------------------------------------------------------
# JWT analyser
# ---------------------------------------------------------------------------

class JWTAnalyser:
    """
    Performs fully offline JWT analysis — no network calls required.

    All cracking logic is self-contained; it operates on raw token strings
    and reconstructs HMAC digests internally.
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyse(self, token: str) -> List[JWTFinding]:
        """
        Run all checks against *token* and return a list of findings.

        Parameters
        ----------
        token:
            A raw JWT string (three base64url-encoded parts separated by dots).
        """
        findings: List[JWTFinding] = []

        try:
            header, payload, signature = self._split(token)
        except ValueError as exc:
            logger.debug("JWT parse error: %s", exc)
            return findings

        preview = token[:40] + "…"

        # Check 1: algorithm = none
        alg = header.get("alg", "").lower()
        if alg == "none":
            findings.append(
                JWTFinding(
                    issue="Algorithm 'none' Accepted",
                    token_preview=preview,
                    details=(
                        "The JWT header declares `alg: none`, meaning the server "
                        "may accept unsigned tokens and skip signature validation "
                        "entirely.  This allows arbitrary claim forgery."
                    ),
                    severity="Critical",
                )
            )

        # Check 2: signature stripping (non-empty token with empty/stripped sig)
        raw_sig = token.split(".")[2] if token.count(".") == 2 else ""
        if raw_sig == "" and alg != "none":
            findings.append(
                JWTFinding(
                    issue="Signature Stripped",
                    token_preview=preview,
                    details=(
                        "The JWT has a non-`none` algorithm header but an empty "
                        "signature segment.  If the server accepts this, signature "
                        "validation is bypassed."
                    ),
                    severity="Critical",
                )
            )

        # Check 3: weak HMAC secret
        if alg.startswith("hs"):
            cracked = self._brute_force_hmac(token, alg)
            if cracked is not None:
                findings.append(
                    JWTFinding(
                        issue="Weak HMAC Secret",
                        token_preview=preview,
                        details=(
                            f"The JWT signature was verified with the weak secret "
                            f"'{cracked}'. An attacker can forge arbitrary tokens."
                        ),
                        severity="Critical",
                        cracked_secret=cracked,
                    )
                )

        # Check 4: sensitive data in payload (no encryption)
        sensitive_keys = {"password", "passwd", "secret", "ssn", "credit_card", "cvv"}
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append(
                JWTFinding(
                    issue="Sensitive Data in JWT Payload",
                    token_preview=preview,
                    details=(
                        f"The JWT payload contains potentially sensitive fields: "
                        f"{found_sensitive}. JWTs are base64-encoded, NOT encrypted."
                    ),
                    severity="Medium",
                )
            )

        return findings

    def forge_none_alg(self, token: str) -> Optional[str]:
        """
        Attempt to forge a `none`-algorithm variant of *token* with the
        `sub` claim elevated to a common admin identifier.

        Returns the forged token string, or None if the input is malformed.
        """
        try:
            header, payload, _ = self._split(token)
        except ValueError:
            return None

        header["alg"] = "none"
        payload["sub"] = payload.get("sub", "1")
        payload["role"] = "admin"
        payload["is_admin"] = True

        new_header = self._b64_encode(json.dumps(header, separators=(",", ":")))
        new_payload = self._b64_encode(json.dumps(payload, separators=(",", ":")))
        return f"{new_header}.{new_payload}."

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _split(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Expected 3 JWT parts, got {len(parts)}")
        header = json.loads(self._b64_decode(parts[0]))
        payload = json.loads(self._b64_decode(parts[1]))
        signature = self._b64_decode_bytes(parts[2])
        return header, payload, signature

    @staticmethod
    def _b64_decode(segment: str) -> str:
        padded = segment + "=" * (4 - len(segment) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")

    @staticmethod
    def _b64_decode_bytes(segment: str) -> bytes:
        padded = segment + "=" * (4 - len(segment) % 4)
        return base64.urlsafe_b64decode(padded)

    @staticmethod
    def _b64_encode(data: str) -> str:
        return (
            base64.urlsafe_b64encode(data.encode("utf-8"))
            .rstrip(b"=")
            .decode("ascii")
        )

    def _brute_force_hmac(self, token: str, alg: str) -> Optional[str]:
        hash_map = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
        hash_fn = hash_map.get(alg.lower())
        if hash_fn is None:
            return None

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = self._b64_decode_bytes(parts[2])

        for candidate in _WEAK_SECRETS:
            key = candidate.encode("utf-8")
            computed = hmac.new(key, signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, expected_sig):
                logger.warning("JWT secret cracked: '%s'", candidate)
                return candidate
        return None


# ---------------------------------------------------------------------------
# OAuth / PKCE checker
# ---------------------------------------------------------------------------

class OAuthChecker:
    """
    Tests OAuth 2.0 authorisation flows for common misconfigurations.

    Checks performed:
      - Missing / predictable `state` parameter (CSRF)
      - PKCE not enforced (code interception possible)
      - `redirect_uri` open-redirect or wildcard acceptance
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._evasion = EvasionEngine()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def check_flow(
        self,
        session: aiohttp.ClientSession,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> List[OAuthFinding]:
        """
        Probe the OAuth authorisation endpoint for common weaknesses.

        Parameters
        ----------
        session:
            An active aiohttp ClientSession.
        auth_endpoint:
            The authorisation server's authorisation URI.
        client_id:
            A valid client_id to use in probe requests.
        redirect_uri:
            The registered redirect URI.
        """
        findings: List[OAuthFinding] = []

        findings.extend(
            await self._check_missing_state(
                session, auth_endpoint, client_id, redirect_uri
            )
        )
        findings.extend(
            await self._check_pkce_enforcement(
                session, auth_endpoint, client_id, redirect_uri
            )
        )
        findings.extend(
            await self._check_open_redirect(
                session, auth_endpoint, client_id, redirect_uri
            )
        )
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    async def _check_missing_state(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> List[OAuthFinding]:
        """Test whether the server rejects authorisation requests without `state`."""
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            # Intentionally omit `state`
        }
        findings: List[OAuthFinding] = []
        try:
            headers = self._evasion.build_headers()
            async with session.get(
                endpoint, params=params, headers=headers, allow_redirects=False
            ) as resp:
                if resp.status in (200, 302):
                    findings.append(
                        OAuthFinding(
                            issue="Missing State Parameter Not Rejected",
                            url=endpoint,
                            details=(
                                "The authorisation endpoint returned a "
                                f"{resp.status} response when the `state` parameter "
                                "was omitted.  This enables CSRF attacks against the "
                                "OAuth flow."
                            ),
                            severity="High",
                        )
                    )
        except (aiohttp.ClientError, Exception) as exc:  # pylint: disable=broad-except
            logger.debug("OAuth state probe error: %s", exc)
        return findings

    async def _check_pkce_enforcement(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> List[OAuthFinding]:
        """
        Test whether PKCE is enforced by sending a code_challenge_method
        without the matching code_challenge.
        """
        findings: List[OAuthFinding] = []
        state = secrets.token_urlsafe(16)
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            # No code_challenge — PKCE omitted
        }
        try:
            headers = self._evasion.build_headers()
            async with session.get(
                endpoint, params=params, headers=headers, allow_redirects=False
            ) as resp:
                if resp.status in (200, 302):
                    findings.append(
                        OAuthFinding(
                            issue="PKCE Not Enforced",
                            url=endpoint,
                            details=(
                                "The authorisation endpoint accepted a request "
                                "without a PKCE `code_challenge`.  Public clients "
                                "are vulnerable to authorisation code interception."
                            ),
                            severity="Medium",
                        )
                    )
        except (aiohttp.ClientError, Exception) as exc:  # pylint: disable=broad-except
            logger.debug("PKCE probe error: %s", exc)
        return findings

    async def _check_open_redirect(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        client_id: str,
        original_redirect: str,
    ) -> List[OAuthFinding]:
        """
        Attempt to substitute a malicious redirect_uri and check whether
        the server validates it against a whitelist.
        """
        findings: List[OAuthFinding] = []
        evil_redirects = [
            "https://evil.com/callback",
            f"{original_redirect}@evil.com",
            f"{original_redirect}//evil.com",
            original_redirect.replace(
                urllib.parse.urlparse(original_redirect).netloc,
                "evil.com",
            ),
        ]
        for evil_uri in evil_redirects:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": evil_uri,
                "state": secrets.token_urlsafe(16),
            }
            try:
                headers = self._evasion.build_headers()
                async with session.get(
                    endpoint, params=params, headers=headers, allow_redirects=False
                ) as resp:
                    location = resp.headers.get("Location", "")
                    parsed_location = urllib.parse.urlparse(location)
                    redirected_to_evil = (
                        parsed_location.netloc == "evil.com"
                        or parsed_location.netloc.endswith(".evil.com")
                    )
                    if redirected_to_evil or resp.status == 200:
                        findings.append(
                            OAuthFinding(
                                issue="Open Redirect / redirect_uri Bypass",
                                url=endpoint,
                                details=(
                                    f"The server did not reject redirect_uri='{evil_uri}'. "
                                    "An attacker may be able to steal authorisation codes."
                                ),
                                severity="Critical",
                            )
                        )
                        break  # One finding per endpoint is enough
            except (aiohttp.ClientError, Exception) as exc:  # pylint: disable=broad-except
                logger.debug("Open-redirect probe error (%s): %s", evil_uri, exc)
        return findings
