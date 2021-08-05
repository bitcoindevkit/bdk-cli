# bdk-cli lib and example bin tool

![CI](https://github.com/bitcoindevkit/bdk-cli/workflows/CI/badge.svg)
![Code Coverage](https://github.com/bitcoindevkit/bdk-cli/workflows/Code%20Coverage/badge.svg)

## About

This project provides a command line interface (cli) Bitcoin wallet library and [`REPL`](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop)
wallet tool based on the [bdk](https://github.com/bitcoindevkit/bdk) library.

## Install bdk-cli
### From source
To install dev version of `bdk-cli` from local git repo:

```shell
cd <bdk-cli git repo directory>
cargo install --path .
bdk-cli help # to verify it worked
```

By default the `electrum` client feature is enabled, to use the `esplora` or another blockchain backend
client instead the default features must be disabled and the desired client feature enabled. Below
is an example of how to enable the `esplora` blockchain client feature instead of `electrum`.

```shell
RUST_LOG=debug cargo run --no-default-features --features repl,esplora -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

If no blockchain client feature is enabled then online wallet commands are disabled.

### From crates.io
You can the install the binaries for the latest tag of `bdk-cli` directly from [crates.io](https://crates.io/crates/bdk-cli) like so:
```sh
cargo install bdk-cli 
```

### bdk-cli bin usage examples

To get usage information for the `bdk-cli` bin use the below command which returns a list of
available wallet options and commands:

```shell
cargo run
```

To sync a wallet to the default electrum server:

```shell
cargo run -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To sync a wallet to Bitcoin Core node (assuming a regtest node at 127.0.0.1:18444) serving compact filters:
Note: 
- This will increase build time by few minutes for the binaries because of `librocksdb`.
- Bitcoin Core v0.21.0 or higher is required to serve compact filters.  

```shell
cargo run --no-default-features --features repl,compact_filters -- --network regtest wallet --node 127.0.0.1:18444 --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To get a wallet balance with customized logging:

```shell
RUST_LOG=debug,sled=info,rustls=info cargo run -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" get_balance
```

To generate a new extended master key, suitable for using in a descriptor:

```shell
cargo run -- key generate
```
