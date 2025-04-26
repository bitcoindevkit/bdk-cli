# Changelog
Changelog information can be found in each release's git tag and can be viewed with `git tag -ln100 "v*"`.
Changelog info is also documented on the [GitHub releases](https://github.com/bitcoindevkit/bdk-cli/releases)
page. See [DEVELOPMENT_CYCLE.md](DEVELOPMENT_CYCLE.md) for more details.

## [Unreleased]
- Add support for generic BIP-322 signed message formats.

## [0.27.1]
- Added hardware signers through the use of HWI.
- Bumped rustc stable to 1.65.
- Bumped electrsd version to v0.22.*.

## [0.26.0]
 - Check that a `PSBT` is signed before broadcast, else throw a useful error message to user.
 - Miniscript Translation capability to an `AliasMap` in wasm, to enhance the paly ground interface.
 - cli-app framework from `structop` to `clap`.
 - Temporarily disable `compact_filters` until `bdk v1.0.0` launch.

## [0.6.0]

- Add distinct `key-value-db` and `sqlite-db` features, keep default as `key-value-db`
- Reorganize existing codes in separate modules. Change crate type from lib to bin.
- Rewrite relevant doc comments as `structopt` help document.
- Update `bdk` and `bdk-reserves` to v0.22.0.
- Change default database to `sqlite`.
- Change the `esplora-reqwest` feature to always use async mode
- Change rpc `--skip-blocks` option to `--start-time` which specifies time initial sync will start scanning from.
- Add new `bdk-cli node <command> [<args>]` to control the backend node deployed by `regtest-*` features.
- Add an integration testing framework in `src/tests/integration.rs`. This framework uses the `regtest-*` feature to run automated testing with bdk-cli.
- Add possible values for `network` option to improve help message, and fix typo in doc.
- Add a module `wasm` containing objects to use bdk-cli from web assembly

## [0.5.0]

- Re-license to dual MIT and Apache 2.0 and update project name to "Bitcoin Dev Kit"
- Update to bdk and bdk-reserves to `0.18.0`
- Add 'verify' feature flag which enables transaction verification against consensus rules during sync.
- Add experimental `regtest-*` features to automatically deploy local regtest nodes
(bitcoind, and electrs) while running cli commands.
- Put cached wallet data in separate directories: ~/.bdk-bitcoin/<wallet_name>
- New MSRV set to `1.56`

## [0.4.0]

- Replace `wallet bump_fee` command `--send_all` with new `--shrink` option
- Add 'reserve' feature to enable proof of reserve
- If no wallet name is provided, derive one from the descriptor instead of using "main"
- Add optional cookie authentication for rpc backend

## [0.3.0]

- Add RPC backend support, after bdk v0.12.0 release
- Update default feature to not include electrum
- Upgrade to `bdk` v0.12.x
- Add top level command "Compile" which compiles a miniscript policy to an output descriptor
- Add `CompactFilterOpts` to `WalletOpts` to enable compact-filter blockchain configuration
- Add `verbose` option to `WalletOpts` to display PSBTs and transaction details also in JSON format
- Require at most one blockchain client feature be enabled at a time
- Change default esplora server URL to https://blockstream.info/testnet/api/ to match default testnet network

## [0.2.0]

- Add support for `wasm`
- Upgrade `bdk` to `0.4.0` and `bdk-macros` to `0.3.0`
- A wallet without a `Blockchain` is used when handling offline wallet sub-commands
- Add top level commands "wallet", "key", and "repl"
- Add "key" sub-commands to "generate" and "restore" a master private key
- Add "key" sub-command to "derive" an extended public key from a master private key
- "repl" command now has an "exit" sub-command
- "wallet" sub-commands and options must be proceeded by "wallet" command
- "repl" command loop now includes both "wallet" and "key" sub-commands

## [0.1.0]

- Add CONTRIBUTING.md
- Add CI and code coverage Discord badges to the README
- Add CI and code coverage github actions workflows
- Add scheduled audit check in CI
- Add CHANGELOG.md
- If an invalid network name return an error instead of defaulting to `testnet`

## [0.1.0-beta.1]

[unreleased]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.27.1...HEAD
[0.27.1]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.26.0...v0.27.1
[0.26.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.6.0...v0.26.0
[0.6.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-cli/compare/0.1.0-beta.1...v0.1.0
[0.1.0-beta.1]: https://github.com/bitcoindevkit/bdk-cli/compare/84a02e35...0.1.0-beta.1
