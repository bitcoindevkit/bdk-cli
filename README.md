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
    <a href="https://blog.rust-lang.org/2020/08/27/Rust-1.56.0.html"><img alt="Rustc Version 1.56+" src="https://img.shields.io/badge/rustc-1.56%2B-lightgrey.svg"/></a>
    <a href="https://discord.gg/d7NkDKm"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
  </p>

  <h4>
    <a href="https://bitcoindevkit.org">Project Homepage</a>
    <span> | </span>
    <a href="https://docs.rs/bdk-cli">Documentation</a>
  </h4>
</div>


## About

This project provides a command-line Bitcoin wallet application using the latest [BDK APIs](https://docs.rs/bdk/0.19.0/bdk/wallet/struct.Wallet.html). This is used mostly as an high level integration testing framework, by the BDK team, using the [tests](/tests/integration.rs) modules.

But if you are planning to use BDK in your own wallet project, bdk-cli is a nice playground to get started with. It allows easy testnet and regtest wallet operations, to try out whats possible with descriptors, miniscripts, and BDK APIs. For more information on BDK refer the [website](https://bitcoindevkit.org/), and the [rust docs](https://docs.rs/bdk/latest/bdk/index.html)

bdk-cli can be compiled in various different ways to suit the experimental needs.
  - Database Options
     - `key-value-db` : Sets the wallet database a `sled` db.
     - `sqlite-db` : Sets the wallet database as `sqlite3` db.
  - Blockchain Options
     - `rpc` : Connects the wallet to bitcoin core via RPC.
     - `electrum` : Connects the wallet to an electrum server.
     - `compact_filters` : Deploy a BIP157 node to get blockchain data from bitcoin p2p network.
     - `esplora-ureq/reqwest` : Connects the wallet to a esplora server sync/asynchronously.
  - Extra Utility Tools
     - `repl` : use bdk-cli as a [REPL](https://codewith.mu/en/tutorials/1.0/repl) shell (useful for quick hand testing wallet operations).
     - `compiler` : opens up bdk-cli policy compiler commands.
     - `verify` : uses `bitcoinconsensus` to verify transactions at every `sync` call of the wallet.
     - `reserves` : opens up bdk-cli **Proof of Reserves** operation commands using the [bdk-reserves plugin](https://github.com/weareseba/bdk-reserves). (requires `electrum`)
   - Automated Node Backend
     - `regtest-bitcoin` : Auto deploys a regtest bitcoin node, connects the wallet, and exposes core rpc commands via `bdk-cli node` subsommands.
     - `regtest-electrum` : Auto deploys a `electrsd` connected to a `bitcoind` and an wallet connectded to `electrsd`. `bdk-cli node` subcommand still calls the `bitcoind` RPC.

The `deafult` feature sets are `repl` and `sqlite-db`. With `default` features, `bdk-cli` works as an **air-gapped** wallet, and can do everything that doesn't require a network connection.


## Install bdk-cli
### From source
To install dev version of `bdk-cli` from local git repo with the `electrum` blockchain client enabled:

```shell
cd <bdk-cli git repo directory>
cargo install --path . --features electrum
bdk-cli help # to verify it worked
```

If no blockchain client feature is enabled online wallet commands `sync` and `broadcast` will be 
disabled. To enable these commands a blockchain client features such as `electrum` or another 
blockchain client feature must be enabled. Below is an example of how run the `bdk-cli` bin with
the `esplora-ureq` blockchain client feature.

```shell
RUST_LOG=debug cargo run --features esplora-ureq -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

At most one blockchain feature can be enabled, available blockchain client features are:
`electrum`, `esplora-ureq` (blocking), `esplora-reqwest` (async), `compact_filters` and `rpc`.

### From crates.io
You can the install the binaries for the latest tag of `bdk-cli` with online wallet features 
directly from [crates.io](https://crates.io/crates/bdk-cli) with a command as below:
```sh
cargo install bdk-cli --features electrum
```

### bdk-cli bin usage examples

To get usage information for the `bdk-cli` bin use the below command which returns a list of
available wallet options and commands:

```shell
cargo run
```

To sync a wallet to the default electrum server:

```shell
cargo run --features electrum -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To sync a wallet to Bitcoin Core node (assuming a regtest node at 127.0.0.1:18443) using the core rpc:

```shell
cargo run --features rpc -- --network regtest wallet --node 127.0.0.1:18443 --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To sync a wallet to Bitcoin Core node (assuming a regtest node at 127.0.0.1:18444) serving compact filters:
Note: 
- This will increase build time by few minutes for the binaries because of `librocksdb`.
- Bitcoin Core v0.21.0 or higher is required to serve compact filters.  

```shell
cargo run --features compact_filters -- --network regtest wallet --node 127.0.0.1:18444 --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To get a wallet balance with customized logging:

```shell
RUST_LOG=debug,sled=info,rustls=info cargo run -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" get_balance
```

To generate a new extended master key, suitable for using in a descriptor:

```shell
cargo run -- key generate
```

## Resources
Docs: [bitcoindevkit.org CLI Section](https://bitcoindevkit.org/bdk-cli/installation/)  
Episode on the _Bitcoin Developers Show_: [Youtube](https://www.youtube.com/watch?v=-Q8OD8NCEe4)  
Video Tutorials: [Youtube Playlist](https://www.youtube.com/playlist?list=PLmyfVqsSelG3jSobvpY3GoNKDtAumsrg3)  
