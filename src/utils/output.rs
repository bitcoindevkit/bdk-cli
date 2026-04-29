use crate::error::BDKCliError as Error;
use cli_table::{CellStruct, Table};
use serde::Serialize;

/// A trait for types that can be presented to the user.
pub trait FormatOutput: Serialize {
    /// Return a pretty table representation.
    fn to_table(&self) -> Result<String, Error>;

    /// Formats the output based on the user's `--pretty` flag.
    fn format(&self, pretty: bool) -> Result<String, Error> {
        if pretty {
            self.to_table()
        } else {
            serde_json::to_string_pretty(self)
                .map_err(|e| Error::Generic(format!("JSON serialization failed: {e}")))
        }
    }
}

/// Helper for building simple tables
pub fn simple_table(
    rows: Vec<Vec<CellStruct>>,
    title: Option<Vec<CellStruct>>,
) -> Result<String, Error> {
    let mut table = rows.table();
    if let Some(title) = title {
        table = table.title(title);
    }
    table
        .display()
        .map_err(|e| Error::Generic(e.to_string()))
        .map(|t| t.to_string())
}
