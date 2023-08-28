<div align="center">
  <h1>BDK-CLI</h1>

  <img src="https://github.com/bitcoindevkit/bdk/raw/master/static/bdk.png" width="220" />

  <p>
    <strong>A Command-line Bitcoin Wallet App in pure rust using BDK</strong>
  </p>

  <p>
    <a href="https://crates.io/crates/bdk-cli"><img alt="Crate Info" src="https://img.shields.io/crates/v/bdk-cli.svg"/></a>
    <a href="https://github.com/bitcoindevkit/bdk-cli/blob/master/LICENSE"><img alt="MIT or Apache-2.0 Licensed" src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg"/></a>
    <a href="https://github.com/bitcoindevkit/bdk-cli/actions?query=workflow%3ACI"><img alt="CI Status" src="https://github.com/bitcoindevkit/bdk-cli/workflows/CI/badge.svg"></a>
    <a href="https://codecov.io/gh/bitcoindevkit/bdk-cli"><img src="https://codecov.io/gh/bitcoindevkit/bdk-cli/branch/master/graph/badge.svg"/></a>
    <a href="https://docs.rs/bdk-cli"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-bdk_cli-green"/></a>
    <a href="https://blog.rust-lang.org/2021/12/02/Rust-1.57.0.html"><img alt="Rustc Version 1.57.0+" src="https://img.shields.io/badge/rustc-1.57.0%2B-lightgrey.svg"/></a>
    <a href="https://discord.gg/d7NkDKm"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
  </p>

  <h4>
    <a href="https://bitcoindevkit.org">Project Homepage</a>
    <span> | </span>
    <a href="https://docs.rs/bdk-cli">Documentation</a>
  </h4>
</div>


## About

This project provides a command-line Bitcoin wallet application using the latest [BDK APIs](https://docs.rs/bdk/latest/bdk/wallet/struct.Wallet.html). This might look tiny and innocent, but by harnessing the power of BDK it provides a powerful generic descriptor based command line wallet tool.
And yes, it can do Taproot!!

This crate can be used for the following purposes:
 - Instantly create a miniscript based wallet and connect to your backend of choice (Electrum, Esplora, Core RPC, etc) and quickly play around with your own complex bitcoin scripting workflow. With one or many wallets, connected with one or many backends.
 - The `tests/integration.rs` module is used to document high level complex workflows between BDK and different Bitcoin infrastructure systems, like Core, Electrum and Lightning(soon TM).
 - (Planned) Expose the basic command handler via `wasm` to integrate `bdk-cli` functionality natively into the web platform. See also the [playground](https://bitcoindevkit.org/bdk-cli/playground/) page.

If you are considering using BDK in your own wallet project bdk-cli is a nice playground to get started with. It allows easy testnet and regtest wallet operations, to try out what's possible with descriptors, miniscript, and BDK APIs. For more information on BDK refer to the [website](https://bitcoindevkit.org/) and the [rust docs](https://docs.rs/bdk/latest/bdk/index.html)

bdk-cli can be compiled with different features to suit your experimental needs.
  - Database Options
     - `key-value-db` : Sets the wallet database to a `sled` db.
     - `sqlite-db` : Sets the wallet database to a `sqlite3` db.
  - Blockchain Options
     - `rpc` : Connects the wallet to bitcoin core via RPC.
     - `electrum` : Connects the wallet to an electrum server.
     - `esplora-ureq` or `esplora-reqwest` : Connects the wallet to an esplora server synchronously or asynchronously.
  - Extra Utility Tools
     - `repl` : use bdk-cli as a [REPL](https://codewith.mu/en/tutorials/1.0/repl) shell (useful for quick manual testing of wallet operations).
     - `compiler` : opens up bdk-cli policy compiler commands.
     - `verify` : uses `bitcoinconsensus` to verify transactions at every `sync` call of the wallet.
     - `reserves` : opens up bdk-cli **Proof of Reserves** operation commands using the [bdk-reserves plugin](https://github.com/bitcoindevkit/bdk-reserves). (requires the `electrum` feature)
   - Automated Node Backend
     - `regtest-bitcoin` : Auto deploys a regtest `bitcoind` node, connects the wallet, and exposes core rpc commands via `bdk-cli node` subcommands.
     - `regtest-electrum` : Auto deploys `electrsd` and connected `bitcoind` nodes, exposes core rpc commands via `bdk-cli node` and provides a wallet connected to the local `electrsd`.
    
The `default` feature set is `repl` and `sqlite-db`. With the `default` features, `bdk-cli` can be used as an **air-gapped** wallet, and can do everything that doesn't require a network connection.


## Install bdk-cli
### From source
To install a dev version of `bdk-cli` from a local git repo with the `electrum` blockchain client enabled:

```shell
cd <bdk-cli git repo directory>
cargo install --path . --features electrum
bdk-cli help # to verify it worked
```

If no blockchain client feature is enabled online wallet commands `sync` and `broadcast` will be 
disabled. To enable these commands a blockchain client feature such as `electrum` or another 
blockchain client feature must be enabled. Below is an example of how to run the `bdk-cli` binary with
the `esplora-ureq` blockchain client feature.

```shell
RUST_LOG=debug cargo run --features esplora-ureq -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

At most one blockchain feature can be enabled, available blockchain client features are:
`electrum`, `esplora-ureq` (blocking), `esplora-reqwest` (async) and `rpc`.

### From crates.io
You can install the binary for the latest tag of `bdk-cli` with online wallet features 
directly from [crates.io](https://crates.io/crates/bdk-cli) with a command as below:
```sh
cargo install bdk-cli --features electrum
```

### bdk-cli bin usage examples

To get usage information for the `bdk-cli` binary use the below command which returns a list of
available wallet options and commands:

```shell
cargo run
```

To sync a wallet to the default electrum server:

```shell
cargo run --features electrum -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To sync a wallet to a Bitcoin Core node (assuming a regtest node at 127.0.0.1:18443) using the core rpc:

```shell
cargo run --features rpc -- --network regtest wallet --node 127.0.0.1:18443 --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To get a wallet balance with customized logging:

```shell
RUST_LOG=debug,sled=info,rustls=info cargo run -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" get_balance
```

To generate a new extended master key, suitable for use in a descriptor:

```shell
cargo run -- key generate
```

## Minimum Supported Rust Version (MSRV)

This library should always compile with any valid combination of features on Rust **1.57.0**.

To build with the MSRV you will need to pin the below dependency versions:

```shell
# log 0.4.19 has MSRV 1.60.0
cargo update -p log --precise 0.4.18
# required for sqlite, hashlink 0.8.2 has MSRV 1.61.0
cargo update -p hashlink --precise 0.8.0
# tempfile 3.7.x has MSRV 1.63.0
cargo update -p tempfile --precise 3.6.0
cargo update -p base64ct --precise 1.5.3
# cc 1.0.82 is throwing error with rust 1.57.0, "error[E0599]: no method named `retain_mut`..."
cargo update -p cc --precise 1.0.81
# tokio 0.30.0 has MSRV 1.63.0
cargo update -p tokio --precise 1.29.1
# flate2 1.0.27 has MSRV 1.63.0+
cargo update -p flate2 --precise 1.0.26
# reqwest 0.11.19 has MSRV 1.63.0+
cargo update -p reqwest --precise "0.11.18"
# h2 0.3.21 has MSRV 1.63.0+
cargo update -p h2 --precise "0.3.20"
# rustls 0.20.9 has MSRV 1.60.0+
cargo update -p rustls --precise "0.20.8"
```

## Resources
Docs: [bitcoindevkit.org CLI Section](https://bitcoindevkit.org/bdk-cli/installation/)  
Episode on the _Bitcoin Developers Show_: [Youtube](https://www.youtube.com/watch?v=-Q8OD8NCEe4)  
Video Tutorials: [Youtube Playlist](https://www.youtube.com/playlist?list=PLmyfVqsSelG3jSobvpY3GoNKDtAumsrg3)  
