# bdk-cli lib and example bin tool

![CI](https://github.com/bitcoindevkit/bdk-cli/workflows/CI/badge.svg)
![Code Coverage](https://github.com/bitcoindevkit/bdk-cli/workflows/Code%20Coverage/badge.svg)

## About

This project provides a command line interface (cli) Bitcoin wallet library and [`REPL`](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop)
wallet tool based on the [bdk](https://github.com/bitcoindevkit/bdk) library.

### bdk-cli bin usage examples

To get usage information for the `bdk-cli` bin use the below command which returns a list of
available wallet options and commands:

```shell
cargo run --features repl,electrum
```

To sync a wallet to the default electrum server:

```shell
cargo run --features repl,electrum,esplora -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" sync
```

To get a wallet balance with customized logging:

```shell
RUST_LOG=debug,sled=info,rustls=info cargo run --features repl,electrum,esplora -- wallet --descriptor "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)" get_balance
```

To generate a new extended master key, suitable for using in a descriptor:

```shell
cargo run --features repl,electrum -- key generate
```

To install dev version of `bdk-cli` from local git repo:

```shell
cd <bdk-cli git repo directory>
cargo install --path . --features repl,electrum,esplora

bdk-cli help # to verify it worked
```