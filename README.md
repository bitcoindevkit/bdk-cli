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
    <a href="https://discord.gg/d7NkDKm"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
  </p>

  <h4>
    <a href="https://bitcoindevkit.org">Project Homepage</a>
    <span> | </span>
    <a href="https://docs.rs/bdk-cli">Documentation</a>
  </h4>
</div>


## About

**EXPERIMENTAL**
This crate has been updated to use `bdk_wallet` 1.x. Only use  for testing on test networks.

This project provides a command-line Bitcoin wallet application using the latest [BDK Wallet APIs](https://docs.rs/bdk_wallet/1.0.0/bdk_wallet/index.html) and chain sources ([RPC](https://docs.rs/bdk_bitcoind_rpc/0.18.0/bdk_bitcoind_rpc/index.html), [Electrum](https://docs.rs/bdk_electrum/0.21.0/bdk_electrum/index.html), [Esplora](https://docs.rs/bdk_esplora/0.21.0/bdk_esplora/), [Kyoto](https://docs.rs/bdk_kyoto/0.9.0/bdk_kyoto/)). This might look tiny and innocent, but by harnessing the power of BDK it provides a powerful generic descriptor based command line wallet tool.
And yes, it can do Taproot!!

This crate can be used for the following purposes:
 - Instantly create a miniscript based wallet and connect to your backend of choice (Electrum, Esplora, Core RPC, Kyoto etc) and quickly play around with your own complex bitcoin scripting workflow. With one or many wallets, connected with one or many backends.
 - The `tests/integration.rs` module is used to document high level complex workflows between BDK and different Bitcoin infrastructure systems, like Core, Electrum and Lightning(soon TM).
 - (Planned) Expose the basic command handler via `wasm` to integrate `bdk-cli` functionality natively into the web platform. See also the [playground](https://bitcoindevkit.org/bdk-cli/playground/) page.

If you are considering using BDK in your own wallet project bdk-cli is a nice playground to get started with. It allows easy testnet and regtest wallet operations, to try out what's possible with descriptors, miniscript, and BDK APIs. For more information on BDK refer to the [website](https://bitcoindevkit.org/) and the [rust docs](https://docs.rs/bdk_wallet/1.0.0/bdk_wallet/index.html)

bdk-cli can be compiled with different features to suit your experimental needs.
  - Database Options
     - `sqlite` : Sets the wallet database to a `sqlite3` db.
  - Blockchain Client Options
     - `esplora` : Connects the wallet to an esplora server.
     - `electrum` : Connects the wallet to an electrum server.
     - `kyoto`: Connects the wallet to a kyoto client and server.
     - `rpc`: Connects the wallet to Bitcoind server.
  - Extra Utility Tools
     - `repl` : use bdk-cli as a [REPL](https://codewith.mu/en/tutorials/1.0/repl) shell (useful for quick manual testing of wallet operations).
     - `compiler` : opens up bdk-cli policy compiler commands.
    
The `default` feature set is `repl` and `sqlite`. With the `default` features, `bdk-cli` can be used as an **air-gapped** wallet, and can do everything that doesn't require a network connection.


## Install bdk-cli

### Prerequisites
Building BDK requires gcc. If you do not have this installed run:
``` shell
sudo apt-get install build-essential
````

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
the `electrum` blockchain client feature.

```shell
RUST_LOG=debug cargo run --features electrum -- --network testnet4 wallet --wallet testnetwallet --ext-descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" --client-type electrum --database-type sqlite --url "ssl://mempool.space:40002" sync
```

Available blockchain client features are:
`electrum`, `esplora`, `kyoto`, `rpc`.

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
cargo run --features electrum -- --network testnet4 wallet --wallet sample_wallet --ext-descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" --database-type sqlite --client-type electrum --url "ssl://mempool.space:40002" sync
```

To get a wallet balance with customized logging:

```shell
RUST_LOG=debug,rusqlite=info,rustls=info cargo run -- wallet --external-descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" balance
```

To generate a new extended master key, suitable for use in a descriptor:

```shell
cargo run -- key generate
```

## Justfile

We have added the `just` command runner to help you with common commands (during development) and running regtest `bitcoind` if you are using the `rpc` feature. 
Visit the [just](https://just.systems/man/en/packages.html) page for setup instructions.

The below are some of the commands included:

``` shell
just # list all available recipes
just test # test the project
just build # build the project
```

### Using `Justfile` to run `bitcoind` as a Client

If you are testing `bdk-cli` in regtest mode and wants to use your `bitcoind` node as a blockchain client, the `Justfile` can help you to quickly do so. Below are the steps to use your `bitcoind` node in *regtest* mode with `bdk-cli`:

Note: You can modify the `Justfile` to reflect your nodes' configuration values. These values are the default values used in `bdk-cli`
 > * default wallet: The set default wallet name is `regtest_default_wallet`
 > * default data directory: The set default data directory is `~/.bdk-bitcoin`
 > * RPC username: The set RPC username is `user`
 > * RPC password: The set RPC password is `password`

#### Steps

1. Start bitcoind
   ```shell
   just start
   ```

2. Create or load a bitcoind wallet with default wallet name

   ```shell
   just create
   ```
   or
   ```shell 
   just load
   ```

3. Generate a bitcoind wallet address to send regtest bitcoins to.

   ```shell
   just address
   ```
   
4. Mine 101 blocks on regtest to bitcoind wallet address
   ```shell
   just generate 101 $(just address)
   ```

5. Check the bitcoind wallet balance
   ```shell
   just balance
   ```

6. Setup your `bdk-cli` wallet config and connect it to your regtest node to perform a `sync`
   ```shell
   export NETWORK=regtest
   export EXT_DESCRIPTOR='wpkh(tprv8ZgxMBicQKsPdMzWj9KHvoExKJDqfZFuT5D8o9XVZ3wfyUcnPNPJKncq5df8kpDWnMxoKbGrpS44VawHG17ZSwTkdhEtVRzSYXd14vDYXKw/0/*)'
   export INT_DESCRIPTOR='wpkh(tprv8ZgxMBicQKsPdMzWj9KHvoExKJDqfZFuT5D8o9XVZ3wfyUcnPNPJKncq5df8kpDWnMxoKbGrpS44VawHG17ZSwTkdhEtVRzSYXd14vDYXKw/1/*)'
   export DATABASE_TYPE=sqlite
   cargo run --features rpc -- wallet -u "127.0.0.1:18443" -c rpc -a user:password sync
   ```

7. Generate an address from your `bdk-cli` wallet and fund it with 10 bitcoins from your bitcoind node's wallet
   ```shell
   export address=$(cargo run --features rpc -- wallet -u "127.0.0.1:18443" -c rpc -a user:password new_address | jq '.address')
   just send 10 $address
   ```

8. Mine 6 more blocks to the bitcoind wallet
   ```shell
   just generate 6 $(just address)
   ```

9. You can `sync` your `bdk-cli` wallet now and the balance should reflect the regtest bitcoin you received
   ```shell
   cargo run --features rpc -- wallet -u "127.0.0.1:18443" -c rpc -a user:password sync
   cargo run --features rpc -- wallet -u "127.0.0.1:18443" -c rpc -a user:password balance
   ```

## Formatting Responses using `--pretty` flag

You can optionally return outputs of commands in  human-readable, tabular format instead of `JSON`. To enable this option, simply add the `--pretty` flag as a top level flag. For instance, you wallet's balance in a pretty format, you can run:

```shell
cargo run --pretty -n signet wallet -w {wallet_name} -d sqlite balance
```
This is available for wallet, key, repl and compile features. When ommitted, outputs default to `JSON`.
