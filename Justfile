set quiet := true
msrv := "1.75.0"
default_wallet := 'regtest_default_wallet'
default_datadir := "$HOME/.bdk-bitcoin"
rpc_user := 'user'
rpc_password := 'password'

# list of recipes
default:
  just --list

# format the project code
fmt:
    cargo fmt

# lint the project
clippy: fmt
    cargo clippy --all-features --tests

# build the project
build: fmt
    cargo build --all-features --tests 

# test the project
test:
    cargo test --all-features --tests 

# clean the project target directory
clean:
    cargo clean

# set the rust version to stable
stable: clean
    rustup override set stable; cargo update

# set the rust version to the msrv and pin dependencies
msrv: clean
    rustup override set {{msrv}}; cargo update; ./ci/pin-msrv.sh

# start regtest bitcoind in default data directory
[group('rpc')]
start:
    if [ ! -d "{{default_datadir}}" ]; then \
        mkdir -p "{{default_datadir}}"; \
    fi
    bitcoind -datadir={{default_datadir}} -regtest -server -fallbackfee=0.0002 -blockfilterindex=1 -peerblockfilters=1 \
     -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} -rpcallowip=0.0.0.0/0 -rpcbind=0.0.0.0 -daemon

# stop regtest bitcoind
[group('rpc')]
stop:
    pkill bitcoind

# stop and delete regtest bitcoind data
[group('rpc')]
reset: stop
    rm -rf {{default_datadir}}

[group('rpc')]
create wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} createwallet {{wallet}}

# load regtest wallet
[group('rpc')]
load wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} loadwallet {{wallet}}

# unload regtest wallet
[group('rpc')]
unload wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} unloadwallet {{wallet}}


# get regtest wallet address
[group('rpc')]
address wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcwallet={{wallet}} -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} getnewaddress

# generate n new blocks to given address
[group('rpc')]
generate n address:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} generatetoaddress {{n}} {{address}}

# get regtest wallet balance
[group('rpc')]
balance wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcwallet={{wallet}} -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} getbalance 

# send n btc to address from wallet
[group('rpc')]
send n address wallet=default_wallet:
    bitcoin-cli -named -datadir={{default_datadir}} -regtest -rpcwallet={{wallet}} -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} sendtoaddress address={{address}} amount={{n}}

# list wallet descriptors info, private = (true | false)
[group('rpc')]
descriptors private wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcwallet={{wallet}} -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} listdescriptors {{private}}

# run any bitcoin-cli rpc command
[group('rpc')]
rpc command wallet=default_wallet:
    bitcoin-cli -datadir={{default_datadir}} -regtest -rpcwallet={{wallet}} -rpcuser={{rpc_user}} -rpcpassword={{rpc_password}} {{command}}