# OODAScan

OODAScan is an experimental web-security research framework organized around an OODA-style workflow: Observe, Orient, Decide, Act.

The project explores how reconnaissance, endpoint classification, assessment state, and structured findings can be coordinated in a repeatable pipeline for controlled security labs and explicitly authorized testing environments.

> **Research / lab tooling:** OODAScan is not a substitute for manual security review. Automated output can contain false positives, miss context-dependent issues, and should always be validated before it is treated as a vulnerability.

## Design

```text
Target / Lab Application
        |
        v
     Observe
        |
        v
      Orient
        |
        v
      Decide
        |
        v
       Act
        |
        +----> structured evidence / findings
        |
        +----> newly discovered application surface
```

The codebase separates the workflow into four main areas:

- `core/` — orchestration, state, and decision logic
- `recon/` — application-surface discovery
- `scanners/` — assessment modules
- `utils/` — shared request and execution helpers

## Project goals

- keep assessment state explicit and reviewable
- separate discovery from decision logic and execution
- use deterministic heuristics where practical
- produce structured evidence rather than opaque conclusions
- support bounded, repeatable experiments in lab environments
- make manual validation part of the workflow

## Installation

```bash
git clone https://github.com/muhammadsohaimmuqtada/OODAScan.git
cd OODAScan
pip install -r requirements.txt
```

Some discovery functionality uses Playwright and therefore requires a local browser installation.

## Scope and limitations

OODAScan is an experimental framework. It does not understand an application's complete business context and cannot independently establish impact or exploitability.

Important limitations include:

- authorization and tenant boundaries require contextual validation
- business-logic findings depend on expected application behavior
- automated endpoint classification can be wrong
- network and application controls can change observed behavior
- scanner output should be treated as a hypothesis until reproduced manually

## Intended use

Use OODAScan only with systems you own, purpose-built training environments, or targets for which you have explicit authorization. Respect the scope, rate limits, account restrictions, data-handling requirements, and stop conditions of the environment being tested.

## Status

This repository is a security-tooling experiment and is expected to evolve as the orchestration model, evidence handling, and validation workflow improve.
