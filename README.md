# ota-artifact-validator

| Field | Value |
|---|---|
| Revision | 1 |
| Created | 2026-06-07 |
| Status | scaffold |
| Part of | [Helix OTA](https://github.com/HelixDevelopment/helix_ota) |
| Language | go |
| License | Apache-2.0 |

## Purpose

OTA artifact validation pipeline: structure, SHA-256 vs hash file, signature, version monotonicity, target compatibility, metadata extraction.

## Boundary (decoupling)

OS-aware via plugins; no transport, no DB. Pure validate(input)->verdict. Reused by the server's upload path and CI.

This is a **reusable, independently versioned** building brick (HelixConstitution
§11.4.28 submodules-as-equal-codebase). It is consumed by Helix OTA and is designed
to be reusable by other projects. It must ship in-depth documentation, user guides,
and full test coverage (§1 four-layer) before leaving `scaffold` status.

## Status

Scaffold. Implementation tracked in the Helix OTA spec corpus
(`docs/research/main_specs/`). See the master design and the submodule reuse map.

## Mirrors

- GitHub: https://github.com/HelixDevelopment/ota-artifact-validator
- GitLab: https://gitlab.com/helixdevelopment1/ota-artifact-validator
