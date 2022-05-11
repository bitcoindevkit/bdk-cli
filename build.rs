use std::env;

fn main() {
    let electrum = env::var_os("CARGO_FEATURE_ELECTRUM").map(|_| "electrum".to_string());
    let esplora = env::var_os("CARGO_FEATURE_ESPLORA").map(|_| "esplora".to_string());
    let compact_filters =
        env::var_os("CARGO_FEATURE_COMPACT_FILTERS").map(|_| "compact_filters".to_string());
    let rpc = env::var_os("CARGO_FEATURE_RPC").map(|_| "rpc".to_string());

    let blockchain_features: Vec<String> = vec![electrum, esplora, compact_filters, rpc]
        .iter()
        .filter_map(|f| f.to_owned())
        .collect();

    if blockchain_features.len() > 1 {
        panic!("At most one blockchain client feature can be enabled but these features were enabled: {:?}", blockchain_features)
    }

    let key_value_db =
        env::var_os("CARGO_FEATURE_KEY_VALUE_DB").map(|_| "key-value-db".to_string());
    let sqlite_db = env::var_os("CARGO_FEATURE_SQLITE_DB").map(|_| "sqlite-db".to_string());

    let database_features: Vec<String> = vec![key_value_db, sqlite_db]
        .iter()
        .map(|f| f.to_owned())
        .flatten()
        .collect();

    if database_features.len() > 1 {
        panic!(
            "At most one database feature can be enabled but these features were enabled: {:?}",
            database_features
        )
    }
}
