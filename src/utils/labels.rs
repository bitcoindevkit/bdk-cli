//! Storage for BIP-329 wallet labels.
//!
//! Labels live in a BIP-329 JSONL file next to the wallet's database,
//! `<datadir>/<wallet>/labels.jsonl`. The file is independent of the wallet's
//! sqlite/redb backend, and is only read by commands that use labels, so a bad
//! labels file can never break unrelated commands such as `balance`.

use crate::error::BDKCliError as Error;
use crate::utils::write_file_content;
use bdk_labels::bip329::LabelRef;
use bdk_labels::{LabelChangeset, LabelPersister, MergeStrategy};
use bdk_wallet::bitcoin::{Address, OutPoint, Txid};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

/// Name of the labels file inside the wallet's data directory.
pub(crate) const LABELS_FILE_NAME: &str = "labels.jsonl";

/// A wallet's labels file.
#[derive(Debug, Clone)]
pub struct LabelStore {
    path: PathBuf,
}

impl LabelStore {
    /// The labels store of `wallet_name`, inside `datadir`.
    pub fn new(datadir: &Path, wallet_name: &str) -> Self {
        Self {
            path: datadir.join(wallet_name).join(LABELS_FILE_NAME),
        }
    }

    /// Load the labels, an absent file is an empty set of labels.
    ///
    /// A file that cannot be read or parsed is an error naming the file.
    pub fn load(&self) -> Result<LabelChangeset, Error> {
        self.read_labels()
            .map_err(|e| Error::LabelsError(bdk_labels::Error::Io(e)))
    }

    /// Load the labels to annotate the output of a command that merely displays them.
    ///
    /// A labels file that cannot be read is reported as a warning and the command
    /// carries on without labels, as listing transactions should not need a healthy
    /// labels file. Commands that set or change labels use [`Self::load`] instead.
    pub fn load_for_display(&self) -> LabelLookup {
        match self.load() {
            Ok(labels) => LabelLookup(labels),
            Err(e) => {
                log::warn!("Not showing labels: {e}");
                LabelLookup(LabelChangeset::new())
            }
        }
    }

    /// An I/O error that names the labels file.
    fn io_error(&self, cause: impl std::fmt::Display) -> io::Error {
        io::Error::other(format!("{}: {cause}", self.path.display()))
    }

    /// Path of the temporary file a write goes through.
    fn temp_path(&self) -> PathBuf {
        self.path.with_extension("jsonl.tmp")
    }
}

/// Labels, looked up by what they label.
#[derive(Debug)]
pub struct LabelLookup(LabelChangeset);

impl LabelLookup {
    /// The label of a transaction.
    pub fn tx(&self, txid: Txid) -> Option<String> {
        self.label(&LabelRef::Txid(txid))
    }

    /// The label of an output (a UTXO, when it is unspent).
    pub fn output(&self, outpoint: OutPoint) -> Option<String> {
        self.label(&LabelRef::Output(outpoint))
    }

    /// The label of an address.
    pub fn address(&self, address: &Address) -> Option<String> {
        self.label(&LabelRef::Address(address.clone().into_unchecked()))
    }

    fn label(&self, target: &LabelRef) -> Option<String> {
        self.0
            .get(target)
            .and_then(|label| label.label())
            .map(str::to_string)
    }
}

impl LabelPersister for LabelStore {
    type Error = io::Error;

    fn read_labels(&self) -> Result<LabelChangeset, Self::Error> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LabelChangeset::new()),
            Err(e) => return Err(self.io_error(e)),
        };

        let mut labels = bdk_labels::import(BufReader::new(file)).map_err(|e| self.io_error(e))?;
        // `import` stages every line it reads, but these labels are already on disk.
        labels.clear_staged();

        Ok(labels)
    }

    /// Merge `changeset` into the file, which is rewritten through a temporary
    /// file and a rename, so an interrupted write cannot leave a truncated file.
    fn append_changeset(&mut self, changeset: &LabelChangeset) -> Result<(), Self::Error> {
        let mut labels = self.read_labels()?;
        labels.merge(changeset.clone(), MergeStrategy::Overwrite);

        let mut jsonl = Vec::new();
        bdk_labels::export(&labels, &mut jsonl).map_err(|e| self.io_error(e))?;
        let jsonl = String::from_utf8(jsonl).map_err(|e| self.io_error(e))?;

        let temp_path = self.temp_path();
        write_file_content(&temp_path, &jsonl).map_err(|e| self.io_error(e))?;
        std::fs::rename(&temp_path, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            self.io_error(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    const TXID_A: &str = "5fe2524f0c46bb12767d1865114031cd631578ac05422a767c0edf23f5c0aeaa";
    const TXID_B: &str = "55d2b85dbf49d78c7070d83f20443e694d90a65498d44bbe84f3c7aa0b55a465";

    /// A store in a fresh data directory with a wallet directory in it.
    fn store() -> (TempDir, LabelStore) {
        let datadir = TempDir::new().unwrap();
        std::fs::create_dir(datadir.path().join("wallet")).unwrap();
        let store = LabelStore::new(datadir.path(), "wallet");
        (datadir, store)
    }

    /// Labels for the given transactions, all staged.
    fn tx_labels(labels: &[(&str, &str)]) -> LabelChangeset {
        let jsonl = labels
            .iter()
            .map(|(txid, label)| format!(r#"{{"type":"tx","ref":"{txid}","label":"{label}"}}"#))
            .collect::<Vec<_>>()
            .join("\n");

        bdk_labels::import(Cursor::new(jsonl)).unwrap()
    }

    #[test]
    fn missing_file_loads_empty() {
        let (_datadir, store) = store();

        let labels = store.load().unwrap();

        assert!(labels.is_empty());
        assert!(!store.path.exists());
    }

    #[test]
    fn corrupt_file_is_an_error_naming_the_file() {
        let (_datadir, store) = store();
        std::fs::write(&store.path, "this is not jsonl\n").unwrap();

        let err = store.load().unwrap_err().to_string();

        assert!(err.contains(LABELS_FILE_NAME), "unexpected error: {err}");
    }

    #[test]
    fn loaded_labels_are_not_staged() {
        let (_datadir, mut store) = store();
        store
            .append_changeset(&tx_labels(&[(TXID_A, "rent")]))
            .unwrap();

        let labels = store.load().unwrap();

        assert_eq!(labels.len(), 1);
        assert!(!labels.has_staged_changes());
    }

    #[test]
    fn appended_changesets_are_merged_with_the_file() {
        let (_datadir, mut store) = store();

        store
            .append_changeset(&tx_labels(&[(TXID_A, "rent")]))
            .unwrap();
        store
            .append_changeset(&tx_labels(&[(TXID_B, "groceries")]))
            .unwrap();
        // A later label for the same transaction replaces the earlier one.
        store
            .append_changeset(&tx_labels(&[(TXID_A, "rent, march")]))
            .unwrap();

        let file = std::fs::read_to_string(&store.path).unwrap();
        assert_eq!(file.lines().count(), 2);
        assert!(file.contains("rent, march"));
        assert!(!file.contains(r#""label":"rent""#));
        assert!(file.ends_with('\n'), "JSONL lines are newline terminated");
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let (_datadir, mut store) = store();

        store
            .append_changeset(&tx_labels(&[(TXID_A, "rent")]))
            .unwrap();

        assert!(store.path.exists());
        assert!(!store.temp_path().exists());
    }

    #[test]
    fn appending_to_a_corrupt_file_fails_and_leaves_it_untouched() {
        let (_datadir, mut store) = store();
        std::fs::write(&store.path, "this is not jsonl\n").unwrap();

        let result = store.append_changeset(&tx_labels(&[(TXID_A, "rent")]));

        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(&store.path).unwrap(),
            "this is not jsonl\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (_datadir, mut store) = store();

        store
            .append_changeset(&tx_labels(&[(TXID_A, "rent")]))
            .unwrap();

        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
