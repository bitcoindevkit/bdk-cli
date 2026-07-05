use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use bdk_wallet::rusqlite::{Connection, ToSql, params, types::ToSqlOutput};
use payjoin::HpkePublicKey;
use payjoin::bitcoin::OutPoint;
use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;

use crate::error::BDKCliError;
use crate::utils::prepare_home_dir;

pub type Result<T> = std::result::Result<T, Error>;

/// Error type for payjoin database operations
#[derive(Debug)]
pub enum Error {
    /// SQLite database error
    Rusqlite(bdk_wallet::rusqlite::Error),
    /// JSON serialization error
    Serialize(serde_json::Error),
    /// JSON deserialization error
    Deserialize(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rusqlite(e) => write!(f, "Database operation failed: {e}"),
            Error::Serialize(e) => write!(f, "Serialization failed: {e}"),
            Error::Deserialize(e) => write!(f, "Deserialization failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Rusqlite(e) => Some(e),
            Error::Serialize(e) => Some(e),
            Error::Deserialize(e) => Some(e),
        }
    }
}

impl From<bdk_wallet::rusqlite::Error> for Error {
    fn from(error: bdk_wallet::rusqlite::Error) -> Self {
        Error::Rusqlite(error)
    }
}

impl From<Error> for payjoin::ImplementationError {
    fn from(error: Error) -> Self {
        payjoin::ImplementationError::new(error)
    }
}

/// Default filename for the payjoin database
pub const DB_FILENAME: &str = "payjoin.sqlite";
const SESSION_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

pub fn open_payjoin_db(
    datadir: Option<PathBuf>,
    wallet_name: &str,
) -> std::result::Result<Arc<Database>, BDKCliError> {
    let wallet_dir = prepare_home_dir(datadir)?.join(wallet_name);
    std::fs::create_dir_all(&wallet_dir).map_err(|e| BDKCliError::Generic(e.to_string()))?;
    let db = Arc::new(Database::create(wallet_dir.join(DB_FILENAME))?);
    db.prune_expired_sessions()?;
    Ok(db)
}

/// Returns the current Unix timestamp in seconds
#[inline]
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .expect("Database mutex should not be poisoned")
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_pubkey BLOB NOT NULL,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES send_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES receive_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS inputs_seen (
                outpoint BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    /// Inserts the input and returns true if the input was seen before, false otherwise.
    /// This is used for replay protection to prevent probing attacks.
    pub fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let key = serialize(&input);
        let was_seen_before = self.conn().execute(
            "INSERT OR IGNORE INTO inputs_seen (outpoint, created_at) VALUES (?1, ?2)",
            params![key, now()],
        )? == 0;
        Ok(was_seen_before)
    }

    /// Removes old completed sessions and stale incomplete sessions plus their event logs.
    pub fn prune_expired_sessions(&self) -> Result<()> {
        let cutoff = now() - SESSION_RETENTION_SECS;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let stale_send_session_ids = {
            let mut stmt = tx.prepare(
                "SELECT session_id FROM send_sessions
                 WHERE (completed_at IS NOT NULL AND completed_at < ?1)
                    OR (
                        completed_at IS NULL
                        AND session_id IN (
                            SELECT session_id FROM send_session_events
                            GROUP BY session_id
                            HAVING MAX(created_at) < ?1
                        )
                    )",
            )?;
            let rows = stmt.query_map(params![cutoff], |row| row.get::<_, i64>(0))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            ids
        };
        let stale_receive_session_ids = {
            let mut stmt = tx.prepare(
                "SELECT session_id FROM receive_sessions
                 WHERE (completed_at IS NOT NULL AND completed_at < ?1)
                    OR (
                        completed_at IS NULL
                        AND session_id IN (
                            SELECT session_id FROM receive_session_events
                            GROUP BY session_id
                            HAVING MAX(created_at) < ?1
                        )
                    )",
            )?;
            let rows = stmt.query_map(params![cutoff], |row| row.get::<_, i64>(0))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            ids
        };
        let deleted_any =
            !stale_send_session_ids.is_empty() || !stale_receive_session_ids.is_empty();

        for session_id in stale_send_session_ids {
            tx.execute(
                "DELETE FROM send_session_events WHERE session_id = ?1",
                params![session_id],
            )?;
            tx.execute(
                "DELETE FROM send_sessions WHERE session_id = ?1",
                params![session_id],
            )?;
        }

        for session_id in stale_receive_session_ids {
            tx.execute(
                "DELETE FROM receive_session_events WHERE session_id = ?1",
                params![session_id],
            )?;
            tx.execute(
                "DELETE FROM receive_sessions WHERE session_id = ?1",
                params![session_id],
            )?;
        }

        tx.commit()?;
        if deleted_any {
            conn.execute("VACUUM", [])?;
        }
        Ok(())
    }

    /// Returns IDs of all active (incomplete) receive sessions
    pub fn get_recv_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT session_id FROM receive_sessions WHERE completed_at IS NULL ORDER BY session_id DESC")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            session_ids.push(session_row?);
        }

        Ok(session_ids)
    }

    /// Returns IDs of all active (incomplete) send sessions
    pub fn get_send_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT session_id FROM send_sessions WHERE completed_at IS NULL ORDER BY session_id DESC")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            session_ids.push(session_row?);
        }

        Ok(session_ids)
    }

    /// Returns the receiver public key for a send session
    pub fn get_send_session_receiver_pk(&self, session_id: &SessionId) -> Result<HpkePublicKey> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT receiver_pubkey FROM send_sessions WHERE session_id = ?1")?;
        let receiver_pubkey: Vec<u8> = stmt.query_row(params![session_id], |row| row.get(0))?;
        Ok(HpkePublicKey::from_compressed_bytes(&receiver_pubkey).expect("Valid receiver pubkey"))
    }

    /// Returns IDs and completion timestamps of all completed send sessions
    pub fn get_inactive_send_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM send_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            session_ids.push(session_row?);
        }
        Ok(session_ids)
    }

    /// Returns IDs and completion timestamps of all completed receive sessions
    pub fn get_inactive_recv_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM receive_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            session_ids.push(session_row?);
        }
        Ok(session_ids)
    }

    /// Formats a Unix timestamp into local date time text.
    pub fn format_unix_timestamp(&self, timestamp: u64) -> Result<String> {
        let Ok(timestamp) = i64::try_from(timestamp) else {
            return Ok(format!("Invalid timestamp ({timestamp})"));
        };
        let conn = self.conn();
        let dt: Option<String> = conn.query_row(
            "SELECT datetime(?1, 'unixepoch', 'localtime')",
            params![timestamp],
            |row| row.get(0),
        )?;
        Ok(dt.unwrap_or_else(|| format!("Invalid timestamp ({timestamp})")))
    }
}

/// Wrapper type for session IDs
#[derive(Debug, Clone)]
pub struct SessionId(i64);

impl ToSql for SessionId {
    fn to_sql(&self) -> bdk_wallet::rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SessionId {
    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

/// Persister for payjoin v2 send sessions
#[derive(Clone)]
pub struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl SenderPersister {
    /// Creates a new sender persister, creating a new session in the database
    pub fn new(db: Arc<Database>, receiver_pubkey: HpkePublicKey) -> Result<Self> {
        let session_id: i64 = db.conn().query_row(
            "INSERT INTO send_sessions (session_id, receiver_pubkey) VALUES (NULL, ?1) RETURNING session_id",
            params![receiver_pubkey.to_compressed_bytes()],
            |row| row.get(0),
        )?;

        Ok(Self {
            db,
            session_id: SessionId(session_id),
        })
    }

    /// Creates a persister from an existing session ID
    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self {
        Self { db, session_id: id }
    }
}

impl SessionPersister for SenderPersister {
    type SessionEvent = SenderSessionEvent;
    type InternalStorageError = Error;

    fn save_event(
        &self,
        event: SenderSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        self.db.conn().execute(
            "INSERT INTO send_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![self.session_id, event_data, now()],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "SELECT event_data FROM send_session_events WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let event_rows = stmt.query_map(params![self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<SenderSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<SenderSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        self.db.conn().execute(
            "UPDATE send_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), self.session_id],
        )?;

        Ok(())
    }
}

/// Persister for payjoin v2 receive sessions
#[derive(Clone)]
pub struct ReceiverPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl ReceiverPersister {
    /// Creates a new receiver persister, creating a new session in the database
    pub fn new(db: Arc<Database>) -> Result<Self> {
        let session_id: i64 = db.conn().query_row(
            "INSERT INTO receive_sessions (session_id) VALUES (NULL) RETURNING session_id",
            [],
            |row| row.get(0),
        )?;

        Ok(Self {
            db,
            session_id: SessionId(session_id),
        })
    }

    /// Creates a persister from an existing session ID
    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self {
        Self { db, session_id: id }
    }
}

impl SessionPersister for ReceiverPersister {
    type SessionEvent = ReceiverSessionEvent;
    type InternalStorageError = Error;

    fn save_event(
        &self,
        event: ReceiverSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        self.db.conn().execute(
            "INSERT INTO receive_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![self.session_id, event_data, now()],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<
        Box<dyn Iterator<Item = ReceiverSessionEvent>>,
        Self::InternalStorageError,
    > {
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "SELECT event_data FROM receive_session_events WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let event_rows = stmt.query_map(params![self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<ReceiverSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<ReceiverSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        self.db.conn().execute(
            "UPDATE receive_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), self.session_id],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use payjoin::HpkeKeyPair;
    use payjoin::persist::SessionPersister as _;
    use payjoin::receive::v2::SessionOutcome as ReceiverSessionOutcome;
    use payjoin::send::v2::SessionOutcome as SenderSessionOutcome;

    use super::*;

    fn sample_receiver_pubkey() -> HpkePublicKey {
        HpkeKeyPair::gen_keypair().1
    }

    fn unique_test_datadir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bdk-cli-payjoin-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn insert_input_seen_before_reports_replays() {
        let db = Database::create(":memory:").expect("in-memory database should open");
        let input = OutPoint::null();

        assert!(
            !db.insert_input_seen_before(input)
                .expect("first insert should succeed"),
            "first observation should not be treated as a replay"
        );
        assert!(
            db.insert_input_seen_before(input)
                .expect("second insert should succeed"),
            "second observation should be treated as a replay"
        );
    }

    #[test]
    fn persisters_round_trip_events_and_transition_sessions() {
        let db = Arc::new(Database::create(":memory:").expect("in-memory database should open"));

        let sender = SenderPersister::new(db.clone(), sample_receiver_pubkey())
            .expect("sender session should be created");
        sender
            .save_event(SenderSessionEvent::PostedOriginalPsbt())
            .expect("sender event should persist");
        sender
            .save_event(SenderSessionEvent::Closed(SenderSessionOutcome::Failure))
            .expect("sender close event should persist");

        let sender_events: Vec<_> = sender.load().expect("sender events should load").collect();
        assert_eq!(
            sender_events,
            vec![
                SenderSessionEvent::PostedOriginalPsbt(),
                SenderSessionEvent::Closed(SenderSessionOutcome::Failure),
            ]
        );

        let active_sender_ids = db
            .get_send_session_ids()
            .expect("active sender ids should load");
        assert_eq!(active_sender_ids.len(), 1);
        assert_eq!(
            db.get_send_session_receiver_pk(&active_sender_ids[0])
                .expect("receiver pubkey should load")
                .to_compressed_bytes()
                .len(),
            33
        );

        sender.close().expect("sender session should close");
        assert!(
            db.get_send_session_ids()
                .expect("active sender ids should load")
                .is_empty()
        );
        assert_eq!(
            db.get_inactive_send_session_ids()
                .expect("inactive sender ids should load")
                .len(),
            1
        );

        let receiver =
            ReceiverPersister::new(db.clone()).expect("receiver session should be created");
        receiver
            .save_event(ReceiverSessionEvent::CheckedBroadcastSuitability())
            .expect("receiver event should persist");
        receiver
            .save_event(ReceiverSessionEvent::Closed(ReceiverSessionOutcome::Cancel))
            .expect("receiver close event should persist");

        let receiver_events: Vec<_> = receiver
            .load()
            .expect("receiver events should load")
            .collect();
        assert_eq!(
            receiver_events,
            vec![
                ReceiverSessionEvent::CheckedBroadcastSuitability(),
                ReceiverSessionEvent::Closed(ReceiverSessionOutcome::Cancel),
            ]
        );

        receiver.close().expect("receiver session should close");
        assert!(
            db.get_recv_session_ids()
                .expect("active receiver ids should load")
                .is_empty()
        );
        assert_eq!(
            db.get_inactive_recv_session_ids()
                .expect("inactive receiver ids should load")
                .len(),
            1
        );
    }

    #[test]
    fn prune_expired_sessions_drops_stale_send_and_receive_rows() {
        let db = Database::create(":memory:").expect("in-memory database should open");
        let stale_timestamp = now() - SESSION_RETENTION_SECS - 1;
        let fresh_timestamp = now();
        let receiver_pubkey = sample_receiver_pubkey();

        db.conn()
            .execute(
                "INSERT INTO send_sessions (session_id, receiver_pubkey, completed_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    1_i64,
                    receiver_pubkey.to_compressed_bytes(),
                    stale_timestamp
                ],
            )
            .expect("stale completed send session should insert");
        db.conn()
            .execute(
                "INSERT INTO send_sessions (session_id, receiver_pubkey, completed_at)
                 VALUES (?1, ?2, NULL)",
                params![2_i64, receiver_pubkey.to_compressed_bytes()],
            )
            .expect("stale active send session should insert");
        db.conn()
            .execute(
                "INSERT INTO send_session_events (session_id, event_data, created_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    2_i64,
                    serde_json::to_string(&SenderSessionEvent::PostedOriginalPsbt())
                        .expect("event should serialize"),
                    stale_timestamp
                ],
            )
            .expect("stale send event should insert");
        db.conn()
            .execute(
                "INSERT INTO send_sessions (session_id, receiver_pubkey, completed_at)
                 VALUES (?1, ?2, NULL)",
                params![3_i64, receiver_pubkey.to_compressed_bytes()],
            )
            .expect("fresh active send session should insert");
        db.conn()
            .execute(
                "INSERT INTO send_session_events (session_id, event_data, created_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    3_i64,
                    serde_json::to_string(&SenderSessionEvent::PostedOriginalPsbt())
                        .expect("event should serialize"),
                    fresh_timestamp
                ],
            )
            .expect("fresh send event should insert");

        db.conn()
            .execute(
                "INSERT INTO receive_sessions (session_id, completed_at) VALUES (?1, ?2)",
                params![4_i64, stale_timestamp],
            )
            .expect("stale completed receive session should insert");
        db.conn()
            .execute(
                "INSERT INTO receive_sessions (session_id, completed_at) VALUES (?1, NULL)",
                params![5_i64],
            )
            .expect("stale active receive session should insert");
        db.conn()
            .execute(
                "INSERT INTO receive_session_events (session_id, event_data, created_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    5_i64,
                    serde_json::to_string(&ReceiverSessionEvent::CheckedBroadcastSuitability())
                        .expect("event should serialize"),
                    stale_timestamp
                ],
            )
            .expect("stale receive event should insert");
        db.conn()
            .execute(
                "INSERT INTO receive_sessions (session_id, completed_at) VALUES (?1, NULL)",
                params![6_i64],
            )
            .expect("fresh active receive session should insert");
        db.conn()
            .execute(
                "INSERT INTO receive_session_events (session_id, event_data, created_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    6_i64,
                    serde_json::to_string(&ReceiverSessionEvent::CheckedBroadcastSuitability())
                        .expect("event should serialize"),
                    fresh_timestamp
                ],
            )
            .expect("fresh receive event should insert");

        db.prune_expired_sessions().expect("pruning should succeed");

        let remaining_send_ids: Vec<i64> = db
            .conn()
            .prepare("SELECT session_id FROM send_sessions ORDER BY session_id")
            .expect("statement should prepare")
            .query_map([], |row| row.get(0))
            .expect("query should execute")
            .map(|row| row.expect("row should decode"))
            .collect();
        assert_eq!(remaining_send_ids, vec![3]);

        let remaining_receive_ids: Vec<i64> = db
            .conn()
            .prepare("SELECT session_id FROM receive_sessions ORDER BY session_id")
            .expect("statement should prepare")
            .query_map([], |row| row.get(0))
            .expect("query should execute")
            .map(|row| row.expect("row should decode"))
            .collect();
        assert_eq!(remaining_receive_ids, vec![6]);
    }

    #[test]
    fn history_lists_active_and_completed_sessions() {
        let datadir = unique_test_datadir("history");
        let wallet_name = "history-wallet";
        let db = open_payjoin_db(Some(datadir.clone()), wallet_name)
            .expect("database should open in temp directory");

        let active_sender = SenderPersister::new(db.clone(), sample_receiver_pubkey())
            .expect("active sender should be created");
        let active_receiver =
            ReceiverPersister::new(db.clone()).expect("active receiver should be created");

        let completed_sender = SenderPersister::new(db.clone(), sample_receiver_pubkey())
            .expect("completed sender should be created");
        completed_sender
            .close()
            .expect("completed sender should close");

        let completed_receiver =
            ReceiverPersister::new(db.clone()).expect("completed receiver should be created");
        completed_receiver
            .close()
            .expect("completed receiver should close");

        let active_send_ids = db
            .get_send_session_ids()
            .expect("active sender ids should load");
        let active_recv_ids = db
            .get_recv_session_ids()
            .expect("active receiver ids should load");
        let inactive_send_ids = db
            .get_inactive_send_session_ids()
            .expect("inactive sender ids should load");
        let inactive_recv_ids = db
            .get_inactive_recv_session_ids()
            .expect("inactive receiver ids should load");

        let table = crate::payjoin::PayjoinManager::history(Some(datadir.clone()), wallet_name)
            .expect("history should render");

        assert!(table.contains("Sender"));
        assert!(table.contains("Receiver"));
        assert!(table.contains(&active_send_ids[0].to_string()));
        assert!(table.contains(&active_recv_ids[0].to_string()));
        assert!(table.contains(&inactive_send_ids[0].0.to_string()));
        assert!(table.contains(&inactive_recv_ids[0].0.to_string()));
        assert!(table.contains("Not Completed"));

        drop(active_sender);
        drop(active_receiver);
        drop(completed_sender);
        drop(completed_receiver);
        drop(db);
        let _ = std::fs::remove_dir_all(datadir);
    }
}
