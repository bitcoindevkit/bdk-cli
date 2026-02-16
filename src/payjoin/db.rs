use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use bdk_wallet::rusqlite::{Connection, params};
use payjoin::HpkePublicKey;
use payjoin::bitcoin::OutPoint;
use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;

use crate::error::PayjoinDbError as Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Default filename for the payjoin database
pub const DB_FILENAME: &str = "payjoin.sqlite";

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
        let receiver_pubkey: Vec<u8> = stmt.query_row(params![session_id.0], |row| row.get(0))?;
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

impl core::ops::Deref for SessionId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
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
            params![*self.session_id, event_data, now()],
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

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
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
            params![now(), *self.session_id],
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
            params![*self.session_id, event_data, now()],
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

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
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
            params![now(), *self.session_id],
        )?;

        Ok(())
    }
}
