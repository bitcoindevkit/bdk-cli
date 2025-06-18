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

[group('wallet')]
init wallet_name ext_descriptor int_descriptor client_type url database_type='sqlite' rpc_user='user' rpc_password='pass' force='false':
    mkdir -p {{default_datadir}}
    # Check if wallet configuration exists
    if [ "{{force}}" = "false" ] && grep -Fx "[wallets.{{wallet_name}}]" {{default_datadir}}/config.toml > /dev/null; then \
        echo "Error: Wallet '{{wallet_name}}' already configured in {{default_datadir}}/config.toml. Use --force to overwrite."; \
        exit 1; \
    fi
    # Remove existing configuration if --force is true
    if [ "{{force}}" = "true" ] && grep -Fx "[wallets.{{wallet_name}}]" {{default_datadir}}/config.toml > /dev/null; then \
        sed -i.bak '/^\[wallets\.{{wallet_name}}\]/,/^\[/d' {{default_datadir}}/config.toml; \
        sed -i.bak '/^\[wallets\.{{wallet_name}}\]/d' {{default_datadir}}/config.toml; \
        rm {{default_datadir}}/config.toml.bak; \
    fi
    # Append new configuration
    echo "" >> {{default_datadir}}/config.toml || touch {{default_datadir}}/config.toml
    echo "[wallets.{{wallet_name}}]" >> {{default_datadir}}/config.toml
    echo "name = \"{{wallet_name}}\"" >> {{default_datadir}}/config.toml
    echo "ext_descriptor = \"{{ext_descriptor}}\"" >> {{default_datadir}}/config.toml
    echo "int_descriptor = \"{{int_descriptor}}\"" >> {{default_datadir}}/config.toml
    echo "database_type = \"sqlite\"" >> {{default_datadir}}/config.toml
    echo "client_type = \"{{client_type}}\"" >> {{default_datadir}}/config.toml
    echo "server_url = \"{{url}}\"" >> {{default_datadir}}/config.toml
    echo "rpc_user = \"{{rpc_user}}\"" >> {{default_datadir}}/config.toml
    echo "rpc_password = \"{{rpc_password}}\"" >> {{default_datadir}}/config.toml
    echo "Wallet configuration for {{wallet_name}} added to {{default_datadir}}/config.toml"
