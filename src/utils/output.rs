use crate::error::BDKCliError as Error;
use serde::Serialize;

/// A trait for types that can be presented to the user.
pub trait FormatOutput: Serialize {
    fn format(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::Generic(format!("JSON serialization failed: {e}")))
    }

    fn print(&self) -> Result<(), Error> {
        let output = self.format()?;
        println!("{}", output);
        Ok(())
    }
}
