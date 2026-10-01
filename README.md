# FlowBound-Nebius

**Governed autonomous software engineering with Nebius Token Factory and NVIDIA Nemotron.**

FlowBound-Nebius is the open-source hackathon implementation of FlowBound's core execution principle:

> AI models may reason and propose freely, but consequential repository mutations must stay inside an explicit, independently enforced authority envelope.

The project is being built for the **Nebius × NVIDIA Global AI Hackathon**. It targets the Coding & Agentic Engineering track by allowing a Nemotron-backed coding agent to inspect a repository, propose changes, edit files, run tests, iterate, and produce a verified result without receiving unrestricted execution authority.

## Why this exists

Most autonomous coding agents focus on increasing capability: more tools, longer context, broader repository access, and fewer human interventions.

FlowBound-Nebius focuses on the complementary problem: **how much autonomy can we safely grant while preserving evidence of what was requested, authorized, executed, and actually observed?**

The model is not the authority source. It cannot grant itself filesystem access, choose arbitrary commands, redefine success, or promote a passing test into a stronger claim such as “secure” or “production ready.”

## Competition architecture

```text
human goal
   |
repository/task intake
   |
NVIDIA Nemotron planning + evidence challenge
   |
structured action proposal
   |
FlowBound authority envelope
   |
deterministic action gate
   |
Nebius-backed bounded execution
   |
independent repository/test observation
   |
accept | block | escalate | recover
   |
execution + verification receipt
```

## Initial authority model

An execution request is bound to a specific repository, branch, predecessor revision, allowed paths, allowed commands, network policy, dependency policy, and claim ceiling.

Example:

```yaml
repository: demo-app
branch: flowbound/task-142
read:
  - src/**
  - tests/**
write:
  - src/parser.py
  - tests/test_parser.py
execute:
  - pytest
  - python -m compileall
deny:
  - .env
  - ~/.ssh/**
  - git push
  - main branch mutation
  - arbitrary network egress
```

A model instruction that conflicts with the envelope is only a proposal. The gate rejects it.

## Planned hackathon demo

1. Give the agent a real repository issue.
2. Nemotron inspects the code and proposes a repair.
3. FlowBound authorizes only the minimum paths and commands needed.
4. The agent edits, tests, diagnoses failure, and iterates.
5. FlowBound independently re-observes the repository and test state.
6. A verified successor state is accepted with a durable receipt.
7. Repeat with a malicious instruction embedded in the repository asking the agent to read secrets, disable tests, or push directly to main.
8. Show the same capable model being blocked because **model intent is not execution authority**.

## Hackathon-period work

This repository is intentionally separate from the pre-existing FlowBound product repository. It is a new Apache-2.0 competition implementation designed around:

- Nebius Token Factory
- NVIDIA Nemotron
- repository-scoped authority envelopes
- iterative plan/edit/test/repair execution
- exact predecessor binding
- bounded filesystem and command capabilities
- information-flow-aware restrictions
- independent successor verification
- intended-vs-observed receipts
- adversarial repository fixtures
- a judge-facing visual execution timeline

The earlier FlowBound Nebius integration established the first live competition adapter and deterministic regression baseline. This repository reimplements only the concepts required for the hackathon submission under an explicitly open-source boundary.

## Status

**Bootstrap / architecture stage.**

Completed:
- public competition repository
- Apache-2.0 licensing boundary
- Nebius/Nemotron competition direction
- prior three-stage Nemotron proposal integration validated in the parent FlowBound competition branch
- prior deterministic suite: 27 passing tests

Next:
- repository authority schema
- command/filesystem gate
- Nemotron coding planner
- bounded execution loop
- independent verifier and receipts
- adversarial demo repository
- live Nebius execution evidence
- hosted demo and Devpost submission

## Security

API keys and credentials must be supplied through environment variables and are never committed. The system is designed to fail closed when an operation is outside the active authority envelope or when expected successor evidence cannot be independently established.

See `SECURITY.md` and `docs/ARCHITECTURE.md` as the implementation lands.

## License

Apache License 2.0.

Copyright 2026 Valentyn Rukhaylo / Altru.dev.
