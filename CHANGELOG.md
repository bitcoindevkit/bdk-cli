# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-cli/compare/0.1.0-beta.1...v0.1.0
[0.1.0-beta.1]: https://github.com/bitcoindevkit/bdk-cli/compare/84a02e35...0.1.0-beta.1
