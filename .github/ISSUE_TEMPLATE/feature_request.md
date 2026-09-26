---
name: Feature request
about: Suggest new capability
title: "[Feature] "
labels: enhancement
assignees: ''
---

## Problem

<!-- What are you trying to accomplish that Sentinel cannot today? -->

## Proposal

<!-- What should be added? -->

## Fit with existing design

Sentinel is a zero-third-party-dependency Python agent with an optional C99
daemon. New engines must be:
- MIT/Apache licensed, or invoked strictly as an external subprocess
- Discovered automatically via `sentinel/core/plugins/` (no registry file)
- Degrading gracefully to an `info` note when their binary is absent

See [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md).

## Alternatives considered

