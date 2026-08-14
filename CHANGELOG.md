# Changelog

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
