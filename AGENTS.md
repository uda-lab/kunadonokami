# Agent Guidelines

<!-- Do not restructure or delete sections. Update individual values in-place when they change. -->

## Core Principles

- Keep this file under 20-30 lines of visible guidance.
- Keep only repo-specific, non-obvious instructions here.

## Project Overview

<!-- Replace this section in-place. Remove the placeholder line once filled. -->
- This file is for coding agents maintaining this repository, not for the runtime Kunadonokami reviewer persona.
- Kunadonokami is a lightweight defensive security review framework for Linux VPS hosts.
- Workflow is owner-side sudo collection, deterministic reduction, read-only AI-assisted review, then human-approved action.
- Treat the local checkout as the control plane; the VPS only needs a reviewed collector copy long enough to create a snapshot.

## Commands

<!-- Replace this section in-place. Remove the placeholder block once filled. -->
~~~sh
scripts/run-vps-collection.sh vps
scripts/collect-vps-security-snapshot.sh /tmp/kunadonokami-snapshot
bash -n scripts/*.sh
~~~

## Code Conventions

<!-- Replace this section in-place. Remove the placeholder line once filled. -->
- Shell entry points are Bash; validate arguments explicitly and keep local diagnostics on stderr.
- Collector scripts may use sudo only on the target VPS and must record per-artifact status before archiving partial snapshots.
- Reducers must be deterministic and auditable; they emit JSON matching schemas/ and never call LLMs, connect to the VPS, run sudo, or mutate configs.

## Architecture

<!-- Replace this section in-place. Remove the placeholder line once filled. -->
- scripts/run-vps-collection.sh is the local control-plane wrapper; avoid VPS repo checkouts or remote curl-to-shell as the default path.
- The Kunadonokami reviewer persona belongs in skills/vps-security-snapshot-reviewer/ and prompts/, not in this repo-maintenance file.
- reducers/ is the planned normalization layer; schemas/ defines reduced artifact contracts; docs/workflow.md is the stage-by-stage authority.

## Maintenance Notes

<!-- This section is permanent. Do not delete. -->
- Delete stale or inferable guidance.
- Update commands and architecture when workflows change.
- Keep durable rules here; move detail to dedicated docs.
