# Changelog

## [0.8.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.7.1...v0.8.0) (2026-08-16)


### Features

* add --format, one machine-output contract across every command ([#51](https://github.com/sirob-tech/boris-mcp-cli/issues/51)) ([0f9acad](https://github.com/sirob-tech/boris-mcp-cli/commit/0f9acade36bb2a0a97c0bf43d445114d095802a0))
* add bmcp list --schemas so one call answers what and how ([#50](https://github.com/sirob-tech/boris-mcp-cli/issues/50)) ([a08d5ee](https://github.com/sirob-tech/boris-mcp-cli/commit/a08d5eeec11da6b937dd06f5bd1d619b5749f1a0))
* answer bmcp doctor from local state and rate limit update checks ([#49](https://github.com/sirob-tech/boris-mcp-cli/issues/49)) ([beb8fca](https://github.com/sirob-tech/boris-mcp-cli/commit/beb8fca850597e0c8ef972c0162e50fbfc654a4e))
* render nested tool schemas and accept conventional CLI discovery forms ([#45](https://github.com/sirob-tech/boris-mcp-cli/issues/45)) ([3817d63](https://github.com/sirob-tech/boris-mcp-cli/commit/3817d63e91c78b2bf664e88193c210a4fd26b218))

## [0.7.1](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.7.0...v0.7.1) (2026-08-14)


### Bug Fixes

* close the silent paths that corrupt the tool catalog and its backups ([#42](https://github.com/sirob-tech/boris-mcp-cli/issues/42)) ([fed247d](https://github.com/sirob-tech/boris-mcp-cli/commit/fed247dc1c26217dbb5fbce1171b590a2b1172f6)), closes [#28](https://github.com/sirob-tech/boris-mcp-cli/issues/28) [#30](https://github.com/sirob-tech/boris-mcp-cli/issues/30) [#31](https://github.com/sirob-tech/boris-mcp-cli/issues/31)
* refresh the instruction tool list on doctor, not only on sync ([#44](https://github.com/sirob-tech/boris-mcp-cli/issues/44)) ([228ff9c](https://github.com/sirob-tech/boris-mcp-cli/commit/228ff9cd3eb5b0292fc689f82b0018e4c9d701f6)), closes [#25](https://github.com/sirob-tech/boris-mcp-cli/issues/25)

## [0.7.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.6.0...v0.7.0) (2026-08-14)


### ⚠ BREAKING CHANGES

* `bmcp doctor --json` writes its JSON document to stdout instead of stderr. Anything reading it off stderr must now read stdout. Prose such as "Syncing tools..." stays on stderr. Human-readable `bmcp doctor` output is unchanged, as is the exit code in both modes.

### Bug Fixes

* answer `--help` and `-h` instead of exiting 1 ([#26](https://github.com/sirob-tech/boris-mcp-cli/issues/26)) ([d4a34d8](https://github.com/sirob-tech/boris-mcp-cli/commit/d4a34d88093cf3c62498265f4533fccfc4b33699))
* move the `doctor --json` document to stdout ([#29](https://github.com/sirob-tech/boris-mcp-cli/issues/29)) ([0e7ea26](https://github.com/sirob-tech/boris-mcp-cli/commit/0e7ea2685727647452d14bb22343f3f2d9e4d2b2))
* refuse to overwrite a good tool cache with an empty catalog ([#27](https://github.com/sirob-tech/boris-mcp-cli/issues/27)) ([01ce332](https://github.com/sirob-tech/boris-mcp-cli/commit/01ce332f278d07be061fd5079c49b608db022a45))

## [0.6.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.5.0...v0.6.0) (2026-08-14)


### Features

* refuse macOS updates that fail signature verification ([#23](https://github.com/sirob-tech/boris-mcp-cli/issues/23)) ([a2f611d](https://github.com/sirob-tech/boris-mcp-cli/commit/a2f611d6b5d47d73ebdf2e4ccb552ab1fd61869e))

## [0.5.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.4.0...v0.5.0) (2026-08-14)


### Features

* self-update with auto-update on doctor, sync and init ([#20](https://github.com/sirob-tech/boris-mcp-cli/issues/20)) ([86a8b85](https://github.com/sirob-tech/boris-mcp-cli/commit/86a8b8536966ca588d439bc5139c83681fba801d))

## [0.4.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.3.0...v0.4.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* `bmcp list` writes NDJSON to stdout instead of two-column text, and the tool-count header moves from stdout to stderr. Pass `--output human` for text output.

### Features

* emit `bmcp list` as NDJSON ([#15](https://github.com/sirob-tech/boris-mcp-cli/issues/15)) ([88cb42c](https://github.com/sirob-tech/boris-mcp-cli/commit/88cb42c02521d037e59854c304cd31c169d90a04)), closes [#11](https://github.com/sirob-tech/boris-mcp-cli/issues/11)


### Bug Fixes

* render every tool in `bmcp list` with the same layout ([#9](https://github.com/sirob-tech/boris-mcp-cli/issues/9)) ([af63d72](https://github.com/sirob-tech/boris-mcp-cli/commit/af63d72737048a681a9d1ff3cba9dd8c7efd579a))

## [0.3.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.2.0...v0.3.0) (2026-07-03)


### Features

* add OpenCode harness support ([#8](https://github.com/sirob-tech/boris-mcp-cli/issues/8)) ([5a6e86f](https://github.com/sirob-tech/boris-mcp-cli/commit/5a6e86f3042d5857419cf9decf86d27767eaf3c1))


### Bug Fixes

* detect shadowed bmcp installations ([#5](https://github.com/sirob-tech/boris-mcp-cli/issues/5)) ([6bb7979](https://github.com/sirob-tech/boris-mcp-cli/commit/6bb7979b08586ccffe3b7e083cc5ee01583a469a))

## [0.2.0](https://github.com/sirob-tech/boris-mcp-cli/compare/v0.1.2...v0.2.0) (2026-06-18)


### Features

* add Kiro install target ([#1](https://github.com/sirob-tech/boris-mcp-cli/issues/1)) ([f777aa4](https://github.com/sirob-tech/boris-mcp-cli/commit/f777aa42ec0215077d91bd55c9826f65d021273f))


### Bug Fixes

* inline BORIS instructions for Codex ([b4c6afc](https://github.com/sirob-tech/boris-mcp-cli/commit/b4c6afc03ce2a05573b4921cde58b833328a128c))
