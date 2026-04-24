use crate::error::BDKCliError as Error;
use serde::Serialize;

/// A trait for data structures that can be rendered to the CLI.
pub trait FormatOutput: Serialize {
    /// Implement this to define how the data looks as a CLI table.
    fn to_table(&self) -> Result<String, Error>;

    /// Formats the output based on the user's `--pretty` flag.
    fn format(&self, pretty: bool) -> Result<String, Error> {
        if pretty {
            self.to_table()
        } else {
            serde_json::to_string_pretty(self).map_err(|e| Error::Generic(e.to_string()))
        }
    }
}
