# bdk-cli lib and example bin tool

![CI](https://github.com/bitcoindevkit/bdk-cli/workflows/CI/badge.svg)
![Code Coverage](https://github.com/bitcoindevkit/bdk-cli/workflows/Code%20Coverage/badge.svg)

## About

This project provides a command line interface (cli) Bitcoin wallet library and [`REPL`](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop)
wallet tool based on the [bdk](https://github.com/bitcoindevkit/bdk) library.

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
blockchain backend feature must be enabled. Below is an example of how run the `bdk-cli` bin with 
the `esplora` blockchain client feature.

```shell
RUST_LOG=debug cargo run --features esplora -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

At most one blockchain feature can be enabled, available blockchain client features are:
`electrum`, `esplora`, and `compact_filters`.

### From crates.io
You can the install the binaries for the latest tag of `bdk-cli` with online wallet features 
directly from [crates.io](https://crates.io/crates/bdk-cli) with a command as below:
```sh
cargo install bdk-cli --features `electrum`
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
