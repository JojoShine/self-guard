# Data access classification implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task.

**Goal:** Explain actual collection coverage and classification-based risk in the existing data security workflow.

**Architecture:** Extend AccessSource JSON mapping configuration, immutable observation assessment snapshots and probe PostgreSQL metadata references. Reuse existing classification policy, finding ingestion and scoped APIs. Additive migration only; existing events/configurations remain readable.

**Tech Stack:** TypeScript/Nest/Prisma/PostgreSQL, React/Ant Design, Go access probe.

**Spec:** docs/superpowers/specs/2026-11-06-data-access-classification-design.md

## Global constraints

- Preserve user changes; no commits, cloud deployment or remote probe installation.
- Keep source/asset/instance authorization and raw-evidence permissions intact.
- HTTP associations are declared configuration, not proof of a database call.
- PostgreSQL references require exact source instance/database/OID/attribute and nonexpired metadata.
- Unknown objects remain unclassified; normal access does not automatically alert.

## Review focus

- An enabled source with stale heartbeat or revoked asset identity must not appear online.
- Identical PostgreSQL OIDs in different databases must not share a mapping.
- Route/method mismatch and stale metadata must not acquire a sensitive classification.
- Failed/unknown reads and below-threshold normal reads must not become sensitive-return alerts.
- Existing events and existing source edits must preserve their historical evidence and scopes.

### Task 1: Actual source status

Files: apps/api/src/access-observation.ts; apps/web/src/AccessSourcesPanel.tsx; related API/Web tests.

- [x] Add failing tests for stale/disabled/configuration/identity states.
- [x] Return safe collection evidence and last effective access for the current scoped page.
- [x] Show version, heartbeat and effective access distinctly; verify focused tests.

### Task 2: Classification mapping

Files: apps/api/prisma/schema.prisma and additive migration; apps/api/src/access-contract.ts; existing access service; services/access-probe/postgres.go and protocol.go; mapping UI and tests.

- [x] Add failing exact-route, scoped OID, stale metadata and malformed frame tests.
- [x] Store validated source object mappings and support scoped HTTP instance association.
- [x] Parse PostgreSQL result metadata references without SQL-name guessing.
- [x] Resolve metadata and snapshot explicit classification coverage; support configured HTTP mappings and read-only metadata snapshot import.
- [x] Verify real protocol bytes, API persistence and unchanged raw evidence.

### Task 3: Risk explanation

Files: existing access service, access source and detail views, finding evidence renderer, tests.

- [x] Add failing threshold and assessment snapshot tests.
- [x] Snapshot actual rule triggers, classification floor and final severity in observations/findings.
- [x] Show ordinary access separately from alerts and explain grading with immutable definitions/versions.
- [x] Verify matching/normal/unknown/partial cases through the existing scoped workflow.

### Task 4: Delivery

- [x] Run focused tests, isolated database acceptance, probe race/build and relevant frontend/API builds.
- [x] Review the patch once and resolve important findings.
- [x] Check local browser desktop/mobile when available; document concrete blockers.
- [x] Record coverage limits and leave Agent migration paused.

Browser check documented as blocked by CUA timeout, not visually passed. New PostgreSQL references verified with actual wire-format fixtures; existing real MySQL/Redis recorded-byte regression passed. No new PostgreSQL live-server or remote deployment claim.
