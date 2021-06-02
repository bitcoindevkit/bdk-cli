# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Project

#### Added
- `CliSubCommand::Compile` enum variant and `handle_compile_subcommand()` function

#### Changed
- Make repl and electrum default features
- Upgrade to `bdk` v0.7.x

### `bdk-cli` bin

#### Added
- New top level command "Compile" which compiles a miniscript policy to an output descriptor
- `CompactFilterOpts` to `WalletOpts` to enable compact-filter blockchain configuration 

#### Changed
- Remove unwraps while handling CLI commands

## [0.2.0]

### Project

#### Added
- Add support for `wasm`
- `CliOpts` struct and `CliSubCommand` enum representing top level cli options and commands
- `KeySubCommand` enum
- `handle_key_subcommand` function

#### Changed
- Upgrade `bdk` to `0.4.0` and `bdk-macros` to `0.3.0`
- Renamed `WalletOpt` struct to `WalletOpts`
- `WalletSubCommand` enum split into `OfflineWalletSubCommand` and `OnlineWalletSubCommand`
- Split `handle_wallet_subcommand` into two functions, `handle_offline_wallet_subcommand` and `handle_online_wallet_subcommand`
- A wallet without a `Blockchain` is used when handling offline wallet sub-commands

### `bdk-cli` bin

#### Added
- Top level commands "wallet", "key", and "repl"
- "key" sub-commands to "generate" and "restore" a master private key
- "key" sub-command to "derive" an extended public key from a master private key
- "repl" command now has an "exit" sub-command

#### Changed
- "wallet" sub-commands and options must be proceeded by "wallet" command
- "repl" command loop now includes both "wallet" and "key" sub-commands

## [0.1.0]

### Project
#### Added
- Add CONTRIBUTING.md
- Add CI and code coverage Discord badges to the README
- Add CI and code coverage github actions workflows
- Add scheduled audit check in CI
- Add CHANGELOG.md

#### Changed
- If an invalid network name return an error instead of defaulting to `testnet`

## [0.1.0-beta.1]

[unreleased]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bitcoindevkit/bdk-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-cli/compare/0.1.0-beta.1...v0.1.0
[0.1.0-beta.1]: https://github.com/bitcoindevkit/bdk-cli/compare/84a02e35...0.1.0-beta.1
