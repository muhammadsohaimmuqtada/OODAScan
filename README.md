# Advanced BB Toolkit

A professional, market-ready bug bounty framework built with Python 3.10+.
It focuses on custom internal logic, asynchronous execution, and advanced
vulnerability classes including OWASP Top 10 and business-logic flaws — with
no reliance on third-party vulnerability APIs.

## Architecture

```
advanced-bb-toolkit/
├── core/
│   └── orchestrator.py       # Async task runner — manages hunt state & task queue
├── scanners/
│   ├── business_logic.py     # HPP, Mass Assignment, Race Conditions, IDOR State Machine
│   └── auth.py               # JWT offline analysis, OAuth state & PKCE checks
├── recon/
│   └── cloud_mapper.py       # Async cloud asset recon (S3, GCP, Azure)
└── utils/
    └── evasion.py            # WAF evasion engine — header rotation, UA rotation, path mutations
```

## Modules

### `core/orchestrator.py`
An `asyncio`-based task runner that manages the complete state of a hunt
session.  It queues and dispatches recon, scanning, and reporting tasks with
configurable concurrency, and tracks discovered endpoints, parameters, and
auth roles in a shared `HuntState` object.

### `scanners/business_logic.py`
Self-contained fuzzer for advanced business-logic vulnerabilities:
- **HTTP Parameter Pollution (HPP)** — duplicates common parameters and
  analyses divergent server behaviour.
- **Mass Assignment** — injects privileged fields (`role`, `is_admin`, etc.)
  into request bodies and checks for acceptance indicators.
- **Race Condition Detection** — fires highly concurrent burst requests and
  flags multiple simultaneous successes.
- **IDOR State Machine** — replays every endpoint across all registered auth
  contexts (Unauthenticated → User A → User B → Admin) and flags Broken
  Access Control when a lower-privilege context receives a substantially
  similar response to the privileged baseline.

### `scanners/auth.py`
Offline authentication vulnerability scanner:
- **JWT Analysis** — checks for the `none` algorithm, signature stripping,
  weak HMAC secrets (internal wordlist, no API), and sensitive data in
  payloads.  Includes a token forger for `none`-alg bypass.
- **OAuth Checks** — validates that the server rejects missing `state`
  parameters (CSRF), enforces PKCE, and validates `redirect_uri` against a
  whitelist.

### `recon/cloud_mapper.py`
Async cloud asset recon scanner:
- Generates dozens of environment/role permutations from the base target name
  (`target-dev`, `target-backup`, `target-staging`, …).
- Probes AWS S3, GCP Cloud Storage, and Azure Blob Storage via direct HTTP
  and classifies responses as `OPEN`, `EXISTS_PROTECTED`, or `NOT_FOUND`.

### `utils/evasion.py`
WAF evasion engine used by every active scanner:
- Rotates User-Agents from a built-in pool.
- Injects and rotates IP-spoofing headers (`X-Forwarded-For`,
  `X-Originating-IP`, `Client-IP`, etc.) with common bypass values.
- Provides path-normalisation mutation helpers (`/./`, `/../`, `/%2f`, …).
- Optional random header-casing to confuse signature-based rules.

## Installation

```bash
pip install -r requirements.txt
```

**Python 3.10+ required.**

## Quick Start

```python
import asyncio
from core.orchestrator import Orchestrator, TaskPriority
from recon.cloud_mapper import CloudMapper
from scanners.business_logic import BusinessLogicScanner, AuthContext
from scanners.auth import JWTAnalyser

TARGET = "example.com"

async def main() -> None:
    orch = Orchestrator(target=TARGET, concurrency=20)

    # Register auth contexts for the IDOR state machine
    orch.state.add_role("unauthenticated", None)
    orch.state.add_role("user_a", "Bearer <token_a>")
    orch.state.add_role("admin",  "Bearer <admin_token>")

    # Cloud recon task
    mapper = CloudMapper()
    orch.enqueue(
        TaskPriority.HIGH, "cloud_recon",
        lambda: mapper.scan(TARGET),
    )

    await orch.run()
    report = orch.get_report()
    print(report)

    # Offline JWT analysis
    analyser = JWTAnalyser()
    findings = analyser.analyse("<your_jwt_here>")
    for f in findings:
        print(f.issue, "-", f.details)

asyncio.run(main())
```

## Requirements

| Library   | Purpose                      |
|-----------|------------------------------|
| `aiohttp` | Async HTTP requests          |
| `PyJWT`   | JWT decoding (reference use) |

## Legal Notice

This toolkit is intended **solely for authorised security testing** on systems
you own or have explicit written permission to test.  Unauthorised use against
third-party systems is illegal.  The authors accept no liability for misuse.