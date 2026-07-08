use std::io::Write;

use crate::error::BDKCliError as Error;
use serde::Serialize;

/// A trait for types that can be presented to the user.
pub trait FormatOutput: Serialize {
    fn format(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::Generic(format!("JSON serialization failed: {e}")))
    }

    fn write_out<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        let output = self.format()?;

        writeln!(writer, "{}", output)
            .map_err(|e| Error::Generic(format!("Failed to write output: {e}")))
    }
}

impl<T: Serialize> FormatOutput for T {}

/// A generic wrapper for commands that return a list of items.
#[derive(Serialize)]
pub struct ListResult<T> {
    pub count: usize,
    pub items: Vec<T>,
}

impl<T> ListResult<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self {
            count: items.len(),
            items,
        }
    }
}
