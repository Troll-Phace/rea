# PSX testing standards

Read ../testing.md and ../../CONTRIBUTING.md before test work. Favor public CLI/MCP and production boundary behavior, with pure parser tests for malformed headers and arithmetic boundaries. Generate synthetic PS-X EXE fixtures from documented source/byte builders; never commit retail or patched game payloads. Include a small known-function oracle, delay slots, load boundaries and unset/uninitialized state. Verify negative admission and cleanup paths as well as success.

Separate deterministic tests, real Ghidra synthetic runs, local patched-AC3 acceptance, and installed-package/fresh-client discovery. No substitute lane proves another. Record exact source/profile/tool versions and source hashes before/after. Application checks have not been run by scaffolding. Use the PLAN.md gates; new tests require npm run verify:test-discovery. Harness validation and unittest helper success do not establish PSX readiness.
