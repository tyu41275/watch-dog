# ADR 0001: Watch Dog MVP and isolation boundary

Status: Proposed placeholder — no product architecture decision accepted  
Date: Pending

## Context

Watch Dog is intended as a WebMCP anti-phishing/community URL-threat-corpus submission. The delivery boundary is less than three days. The parent vision interview and independent multi-model deliberation have not yet occurred.

## Decisions already authorized

- Use a public `tyu41275/watch-dog` repository.
- Use Apache-2.0 for its permissive terms and explicit patent grant.
- Keep the final needs-plan issue gated on completed, persisted vision artifacts.
- Do not implement STIX/TAXII unless deliberation proves it essential to the MVP.

## Decision pending

The product surface, architecture, URL-handling behavior, data sources, verdict policy, storage model, contribution/moderation flow, deployment target, and demo acceptance criteria remain undecided.

## Options to evaluate after the interview

- Smallest credible WebMCP interaction and user journey
- Read-only explanation/check experience versus contribution flow
- Static or curated corpus versus a minimal moderated write path
- Local/static evidence versus external reputation providers
- Safe URL normalization, defanging, and non-navigation controls
- Whether any interoperability format is necessary inside the three-day bound

## Consequences and revisit triggers

To be completed only after independent recommendations are reconciled. The accepted record must name the chosen option, rejected alternatives, safety invariants, deadline tradeoffs, and conditions that would trigger reconsideration.
