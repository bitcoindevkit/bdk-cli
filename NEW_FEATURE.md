
## Adding a command/feature in bdk-cli

The modular architectural redesign (see #278 for the original design discussion) introduced a strict separation of concerns and utilizes a Typestate Pattern to prevent invalid operations. If you are a new contributor looking to add a new command or feature, this guide will walk you through the process step-by-step.


### The Core Architecture at a Glance

Before writing code, it helps to understand the three major components of a bdk-cli command:

__Clap Parser:__ Defines the CLI arguments the user types. 

__The AppCommand Trait__: The trait every command must implement to define its execution logic and return a formatted output. It has the `execute` method and a type `FormatOutput` for formatting the command's response. If the command involves I/O, there is an AsyncAppCommand to use.

__The Typestate (AppContext<T>):__ Defines the environment your command runs in. Every command is a struct that implements the AppCommand's trait execute method against a typestate context. There are three context (src/handlers/mod):

| Context	        | What it Holds         |	When to use            |
|------             |--------               |-------
| AppContext<Init>	| just network, datadir	| needs no wallet and blockchain |
| AppContext<OfflineOperations>	 | wallet	| needs the wallet but not blockchain| 
| AppContext<OnlineOperations>	 | wallet, client, wallet_name	| needs a wallet, and a blockchain backend |

The below table should aid your decision:

|Needs a wallet?	| Does network I/O?	|  Context + trait |
|---                | ---               | ----             |
|   No	            |   No	            | Init + AppCommand |
|   No	            |   Yes	            | Init + AsyncAppCommand |
|   Yes	            |   No	            | OfflineOperations + AppCommand |
|   Yes	            |   Yes (blockchain)| OnlineOperations + AsyncAppCommand|

Note: If your command uses AsyncAppCommand, the execute method signature will be async fn execute(...) and you must .await it in the router.

### Step-by-Step Guide: Adding a Feature

For this tutorial, let's assume we are adding a `WalletDetailsCommand` that operates on a (offline) wallet.

##### Step 1: Define the Command Structure (CLI Arguments)

First, define how the user will interact with your command using clap. Create a struct for your command in the appropriate file (e.g., `src/handlers/offline.rs`).

```Rust
use clap::Parser;

/// Displays advanced details about the wallet.
#[derive(Debug, Parser, Clone, PartialEq)]
pub struct WalletDetailsCommand {
    /// Include the full descriptor strings in the output
    #[arg(short, long, default_value_t = false)]
    pub show_descriptors: bool,
}

```

##### Step 2: Define the Output Type

Every command must return a structured result that can be serialized into standard JSON. Define a struct that implements serde::Serialize ( placed in `src/utils/types.rs`).

```Rust
use serde::Serialize;
use bdk_wallet::bitcoin::Network;

#[derive(Debug, Serialize)]
pub struct WalletDetailsResult {
    pub network: Network,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_descriptor: Option<String>,
}
```

##### Step 3: Implement the AppCommand Trait

Now, tie it together. Implement the AppCommand trait for your command. This is where your actual business logic lives.

Because our command needs to read wallet data, we will use the OfflineOperations typestate.

```Rust
use crate::handlers::{AppCommand, AppContext, OfflineOperations};
use crate::error::BDKCliError as Error;

impl AppCommand<AppContext<OfflineOperations<'_>>> for WalletDetailsCommand {
    // 1. Declare the output type we defined in Step 2
    type Output = WalletDetailsResult;

    // 2. Implement the execute function
    fn execute(&self, context: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        // Access the loaded wallet via the context state
        let wallet = &context.state.wallet;
        
        let network = wallet.network();
        let fingerprint = wallet.fingerprint().to_string();
        
        let external_descriptor = if self.show_descriptors {
            Some(wallet.public_descriptor(bdk_wallet::KeychainKind::External).to_string())
        } else {
            None
        };

        // Return the structured Result
        Ok(WalletDetailsResult {
            network,
            fingerprint,
            external_descriptor,
        })
    }
}
```

##### Step 4: Configure the Database Requirement (Crucial for Offline Commands)

We do not load the database for every offline command. Commands that only do math or parse strings (like CombinePsbt) skip the DB to remain blazing fast. Commands that read state (like Balance or our new Details) need the DB.

Locate the `command_requires_db` function (in src/utils/common.rs) and add your command to the match statement:

```Rust
pub fn command_requires_db(cmd: &OfflineWalletSubCommand) -> bool {
    match cmd {
        // Commands that DO NOT need the database (returns false)
        OfflineWalletSubCommand::CombinePsbt(_) |
        OfflineWalletSubCommand::ExtractPsbt(_) => false,
        
        // Commands that DO need the database (returns true)
        // Add our new Details command here
        OfflineWalletSubCommand::Details(_) |
        OfflineWalletSubCommand::Balance(_) |
        OfflineWalletSubCommand::Transactions(_) => true,
        
        _ => true, // Safe default
    }
}
```

Note: Because of this function, `main` module knows exactly how to boot the WalletRuntime before executing your command.

##### Step 5: Wire it into the Router

Now that the command exists, clap needs to know about it, and the execution router needs to dispatch it.

Locate the enum that holds the subcommands for your specific typestate (e.g., OfflineWalletSubCommand in `src/commands.rs`)

i. Add it to the Enum:

```Rust
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum OfflineWalletSubCommand {
    // ... existing commands ...
    
    // Get advanced details about the wallet
    Details(WalletDetailsCommand),
}
```

ii. Add it to the execution matcher:

In the same module, locate the execute method for that enum and add your new variant. Notice how we call `.execute(ctx)?` and chain it into `.write_out(...)`. This guarantees your output is properly formatted to JSON and written to stdout.

```Rust
impl OfflineWalletSubCommand {
    pub fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<(), Error> {
        match self {
            // ... existing commands ...
            
            Self::Details(details_cmd) => details_cmd
                .execute(ctx)?
                .write_out(std::io::stdout()),
        }
    }
}
```

##### Step 6: Test the command

We use Black-Box integration testing. Open the relevant module in the tests/integration/ directory (e.g., offline.rs) and use the BdkCli helper to test your new feature. Thereafter, ensure everything compiles and pass the relevant checks by running `just pre-push`.
