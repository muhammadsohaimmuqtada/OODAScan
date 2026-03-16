# Advanced BB Toolkit

A professional, market-ready, **fully autonomous** bug bounty framework built
with Python 3.10+.  It implements a self-driving OODA loop (Observe → Orient →
Decide → Act) so the only input required is the target domain — no manual
endpoint feeding, no manual token state switching, no external vulnerability
APIs.

## Architecture

```
advanced-bb-toolkit/
├── cli.py                          # ← CLI entry point  (python cli.py scan …)
├── core/
│   ├── orchestrator.py             # Async task runner + autonomous pipeline entry-point
│   └── autonomous_agent.py         # OODA loop AI engine — the self-driving "Brain"
├── scanners/
│   ├── business_logic.py           # HPP, Mass Assignment, Race Conditions, IDOR State Machine
│   ├── auth.py                     # JWT offline analysis, OAuth state & PKCE checks
│   └── auto_payload_generator.py   # Schema-aware dynamic payload generation
├── recon/
│   ├── cloud_mapper.py             # Async cloud asset recon (S3, GCP, Azure)
│   └── auto_crawler.py             # Headless Playwright DOM crawler & JS analyser
└── utils/
    ├── evasion.py                  # Base WAF evasion engine
    └── auto_evasion.py             # Self-healing WAF auto-tuning with retry loops
```

## Modules

### `core/autonomous_agent.py` *(NEW)*
The self-driving engine.  Implements a full OODA loop:
- **Observe** — probes each URL with evasion-wrapped requests.
- **Orient** — classifies the endpoint as GraphQL, REST, Auth, Admin, or Unknown
  using purely heuristic, pattern-based rules (no LLM API required).
- **Decide** — selects the matching built-in scanner(s) from the action registry.
- **Act** — fires the scanner, collects findings, and feeds any newly discovered
  endpoints back into the queue for the next round.

Built-in actions:
| Endpoint Kind | Actions |
|---|---|
| `GRAPHQL` | Introspection probe, batching abuse |
| `REST_JSON` | IDOR path enumeration, HTTP method enumeration |
| `AUTH` | Default credential testing, JWT issuance analysis |
| `ADMIN_PANEL` | Unauthenticated access check, admin path discovery |
| `UNKNOWN` | Header tech disclosure, stack-trace, hardcoded secret patterns |

### `recon/auto_crawler.py` *(NEW)*
Headless Playwright-based DOM crawler:
- Intercepts all XHR/Fetch API calls made by the SPA in real-time.
- Downloads and statically analyses webpack JS bundles for API routes.
- Scrapes `data-*` attributes and inline `<script>` blocks.
- Flags hardcoded AWS keys, API keys, bearer tokens, and private keys found
  in JavaScript source.
- Feeds the full endpoint list directly into the `AutonomousAgent`.

### `scanners/auto_payload_generator.py` *(NEW)*
Schema-aware dynamic payload generator:
- Infers each field's semantic kind (numeric ID, amount, path, email, …) from
  its name and current value — no static wordlists.
- Generates targeted payloads per kind:
  - **Numeric IDs** → IDOR (`±1`, `0`, `-1`, `2^31`), SQLi, NoSQL, type confusion
  - **Amounts** → business-logic (`-1`, `0`, overflow, `NaN`, `Infinity`)
  - **Strings** → SQLi, NoSQL, XSS, SSTI, format string, path traversal
  - **Paths** → directory traversal, `file://`, URL encoding variants
  - **Booleans** → truthy/falsy coercion variants
- Always appends a mass-assignment mutation injecting admin/privilege fields.

### `utils/auto_evasion.py` *(NEW)*
Self-healing WAF bypass wrapper:
- Detects 403, 429, 503, and known WAF challenge page bodies automatically.
- On each block, rotates through a strategy sequence:
  `rotate_ua` → `rotate_ip` → `rotate_ua_and_ip` → `mutate_path` →
  `add_delay` → `randomise_casing` → `full_rotation`
- Applies exponential back-off with ±50 % jitter between retries.
- Exposes a single `resilient_request()` coroutine used by every scanner.

### `core/orchestrator.py` *(updated)*
Now exposes a `run_autonomous()` method that:
1. Optionally launches `AutoCrawler` to seed endpoints from the live DOM.
2. Instantiates `AutonomousAgent` with any provided auth tokens.
3. Runs the full OODA loop and merges findings back into `HuntState`.

### `scanners/business_logic.py`
Self-contained fuzzer for advanced business-logic vulnerabilities:
- HTTP Parameter Pollution (HPP)
- Mass Assignment
- Race Condition Detection
- IDOR State Machine

### `scanners/auth.py`
Offline authentication vulnerability scanner:
- JWT Analysis (none alg, signature stripping, weak HMAC secrets, payload leaks)
- OAuth Checks (missing state, PKCE enforcement, open redirect)

### `recon/cloud_mapper.py`
Async cloud asset recon scanner (AWS S3, GCP Cloud Storage, Azure Blob).

### `utils/evasion.py`
Base WAF evasion engine — header rotation, UA rotation, path mutations.

## Installation

```bash
pip install -r requirements.txt
playwright install chromium   # Required for AutoCrawler (headless browser)
```

**Python 3.10+ required.**

## Quick Start — CLI (Recommended)

The easiest way to run the toolkit is via the built-in CLI powered by
[Typer](https://typer.tiangolo.com/) and [Rich](https://github.com/Textualize/rich).

```bash
# Minimal autonomous scan
python cli.py scan --target https://example.com

# Full scan with crawler, auth tokens, and JSON report
python cli.py scan \
    --target https://example.com \
    --use-crawler \
    --concurrency 30 \
    --timeout 15 \
    --token-user-a "Bearer eyJ..." \
    --token-user-b "Bearer eyJ..." \
    --token-admin "Bearer eyJ..." \
    --output report.json
```

The CLI will display a live spinner during the scan and then print a colour-coded
findings table to the terminal.  If `--output` is given, the full JSON report is
written to that file.

### CLI Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | *required* | Target URL to scan |
| `--concurrency` | `-c` | `20` | Max simultaneous HTTP requests |
| `--timeout` | | `10.0` | Per-request timeout (seconds) |
| `--use-crawler` | | `False` | Enable headless Playwright crawler |
| `--output` | `-o` | `None` | File path to save JSON report |
| `--token-user-a` | | `None` | Auth token for User A |
| `--token-user-b` | | `None` | Auth token for User B |
| `--token-admin` | | `None` | Auth token for Admin role |

## Quick Start — Python API (Autonomous Mode)

```python
import asyncio
from core.orchestrator import Orchestrator

async def main() -> None:
    orch = Orchestrator(target="https://example.com", concurrency=20)

    report = await orch.run_autonomous(
        use_crawler=True,          # DOM crawl first, then agent takes over
        token_user_a="Bearer eyJ...",
        token_user_b="Bearer eyJ...",
        token_admin="Bearer eyJ...",
    )

    import json
    print(json.dumps(report, indent=2, default=str))

asyncio.run(main())
```

## Advanced Usage — Manual Control

```python
import asyncio
from core.orchestrator import Orchestrator, TaskPriority
from core.autonomous_agent import AutonomousAgent, EndpointKind
from recon.cloud_mapper import CloudMapper
from scanners.auto_payload_generator import AutoPayloadGenerator
from scanners.auth import JWTAnalyser

TARGET = "https://example.com"

async def main() -> None:
    # ── Manual orchestrator ───────────────────────────────────────────
    orch = Orchestrator(target=TARGET, concurrency=20)
    orch.state.add_role("unauthenticated", None)
    orch.state.add_role("user_a", "Bearer <token_a>")
    orch.state.add_role("admin",  "Bearer <admin_token>")

    mapper = CloudMapper()
    orch.enqueue(TaskPriority.HIGH, "cloud_recon", lambda: mapper.scan(TARGET))
    await orch.run()

    # ── Dynamic payload generation ────────────────────────────────────
    gen = AutoPayloadGenerator()
    for mutation in gen.generate({"user_id": 123, "amount": 50.0}):
        print(mutation["_fuzz_meta"])

    # ── Offline JWT analysis ─────────────────────────────────────────
    analyser = JWTAnalyser()
    for f in analyser.analyse("<your_jwt_here>"):
        print(f.issue, "-", f.details)

asyncio.run(main())
```

## Requirements

| Library      | Purpose                                    |
|--------------|--------------------------------------------|
| `aiohttp`    | Async HTTP requests                        |
| `PyJWT`      | JWT decoding (reference use)               |
| `playwright` | Headless browser for AutoCrawler           |
| `typer`      | CLI framework                              |
| `rich`       | Terminal UI (tables, spinners, colours)    |

## Legal Notice

This toolkit is intended **solely for authorised security testing** on systems
you own or have explicit written permission to test.  Unauthorised use against
third-party systems is illegal.  The authors accept no liability for misuse.