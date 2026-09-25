//! The SOCKS5 proxy options must actually reach the blockchain client.
//!
//! These tests stand two TCP listeners in for the chain server and the proxy, so
//! they need neither a real node nor a real SOCKS5 service: all that matters is
//! which port the connection arrives on.
#[cfg(any(feature = "electrum", feature = "esplora", feature = "cbf"))]
mod test_proxy {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    #[cfg(any(feature = "rpc", feature = "cbf"))]
    use predicates::prelude::*;
    use serde_json::Value;
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    use std::net::{TcpListener, TcpStream};
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    use std::sync::mpsc::{Receiver, channel};
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    static WALLET_NAME: &str = "proxy_test_wallet";

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    /// Accept connections on an ephemeral port, reporting each one and closing it
    /// immediately. Returns the bound address and the receiving end of the report.
    fn spawn_listener() -> (String, Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind listener");
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = channel();

        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        drop::<TcpStream>(stream);
                        if tx.send(()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        (addr, rx)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    /// Did a connection arrive within the grace period?
    fn connected(rx: &Receiver<()>) -> bool {
        rx.recv_timeout(Duration::from_secs(5)).is_ok()
    }

    /// Configure a wallet against `url`, optionally through `proxy_addr`, for the
    /// backends that talk to a listener the tests can watch.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn setup_wallet_for(
        client_type: &str,
        url: &str,
        proxy_addr: Option<&str>,
    ) -> (BdkCli, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "wpkh"])
            .output()
            .expect("failed to generate descriptors");
        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("invalid JSON from descriptor");
        let public = &desc_values["public_descriptors"];
        let ext_desc = public["external"].as_str().unwrap();
        let int_desc = public["internal"].as_str().unwrap();

        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallet")
            .arg("--wallet")
            .arg(WALLET_NAME)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(ext_desc)
            .arg("--int-descriptor")
            .arg(int_desc)
            .arg("--client-type")
            .arg(client_type)
            .arg("--database-type")
            .arg("sqlite")
            .arg("--url")
            .arg(url);
        if let Some(proxy) = proxy_addr {
            cmd.arg("--proxy").arg(proxy);
        }
        cmd.assert().success();

        (cli, temp_dir)
    }

    /// Runs `sync` and returns the command, so callers can assert on how it failed.
    fn sync_cmd(cli: &BdkCli) -> Command {
        let mut cmd = cli.wallet_cmd(&["--wallet", WALLET_NAME, "sync"]);
        cmd.timeout(Duration::from_secs(30));
        cmd
    }

    /// Configure a wallet for `client_type` with `extra_args` appended to the
    /// `config` command (e.g. `--proxy`, `--proxy_auth`, `--timeout`). No listener
    /// is needed: these tests only exercise validation, which happens before any
    /// connection is attempted, at `sync` time.
    #[cfg(any(feature = "rpc", feature = "cbf"))]
    fn setup_wallet_with_args(client_type: &str, extra_args: &[&str]) -> (BdkCli, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "wpkh"])
            .output()
            .expect("failed to generate descriptors");
        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("invalid JSON from descriptor");
        let public = &desc_values["public_descriptors"];

        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallet")
            .arg("--wallet")
            .arg(WALLET_NAME)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(public["external"].as_str().unwrap())
            .arg("--int-descriptor")
            .arg(public["internal"].as_str().unwrap())
            .arg("--client-type")
            .arg(client_type)
            .arg("--database-type")
            .arg("sqlite");
        // `--url` is required whenever electrum, esplora or rpc is built, no matter
        // which `--client-type` is chosen; it does not exist at all otherwise.
        #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
        cmd.arg("--url").arg("127.0.0.1:18443");
        cmd.args(extra_args).assert().success();

        (cli, temp_dir)
    }

    /// With `--proxy` set, the connection must go to the proxy and never to the
    /// chain server directly.
    #[cfg(feature = "electrum")]
    #[test]
    fn test_electrum_sync_goes_through_the_proxy() {
        let (server_addr, server_rx) = spawn_listener();
        let (proxy_addr, proxy_rx) = spawn_listener();

        let (cli, _temp_dir) = setup_wallet_for(
            "electrum",
            &format!("tcp://{server_addr}"),
            Some(&proxy_addr),
        );

        // The stub proxy does not speak SOCKS5, so the sync must fail rather than
        // quietly falling back to a direct connection.
        sync_cmd(&cli).assert().failure();

        assert!(
            connected(&proxy_rx),
            "the proxy was never contacted: traffic bypassed --proxy"
        );
        assert!(
            !connected(&server_rx),
            "a direct connection reached the chain server despite --proxy"
        );
    }

    /// Without `--proxy`, the connection goes straight to the chain server. This is
    /// the control: it shows the test above is detecting the proxy, not a failure
    /// to connect at all.
    #[cfg(feature = "electrum")]
    #[test]
    fn test_electrum_sync_without_proxy_goes_direct() {
        let (server_addr, server_rx) = spawn_listener();

        let (cli, _temp_dir) = setup_wallet_for("electrum", &format!("tcp://{server_addr}"), None);

        sync_cmd(&cli).assert().failure();

        assert!(
            connected(&server_rx),
            "no connection reached the chain server"
        );
    }

    /// The esplora backend must honour `--proxy` just as electrum does.
    #[cfg(feature = "esplora")]
    #[test]
    fn test_esplora_sync_goes_through_the_proxy() {
        let (server_addr, server_rx) = spawn_listener();
        let (proxy_addr, proxy_rx) = spawn_listener();

        let (cli, _temp_dir) = setup_wallet_for(
            "esplora",
            &format!("http://{server_addr}"),
            Some(&proxy_addr),
        );

        sync_cmd(&cli).assert().failure();

        assert!(
            connected(&proxy_rx),
            "the proxy was never contacted: traffic bypassed --proxy"
        );
        assert!(
            !connected(&server_rx),
            "a direct connection reached the chain server despite --proxy"
        );
    }

    /// A proxy the backend cannot honour at all is rejected, rather than ignored.
    #[cfg(feature = "rpc")]
    #[test]
    fn test_rpc_backend_rejects_a_proxy() {
        let (cli, _temp_dir) = setup_wallet_with_args("rpc", &["--proxy", "127.0.0.1:9050"]);

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "rpc backend does not support a SOCKS5 proxy",
            ));
    }

    /// `--proxy_auth` alone (no `--proxy`) is also rejected for rpc, not just
    /// silently dropped.
    #[cfg(all(feature = "rpc", any(feature = "electrum", feature = "esplora")))]
    #[test]
    fn test_rpc_backend_rejects_proxy_auth() {
        let (cli, _temp_dir) = setup_wallet_with_args("rpc", &["--proxy_auth", "user:password"]);

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "rpc backend does not support --proxy_auth",
            ));
    }

    /// `--timeout` alone is likewise rejected for rpc.
    #[cfg(all(feature = "rpc", any(feature = "electrum", feature = "esplora")))]
    #[test]
    fn test_rpc_backend_rejects_timeout() {
        let (cli, _temp_dir) = setup_wallet_with_args("rpc", &["--timeout", "30"]);

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "rpc backend does not support --timeout",
            ));
    }

    /// Kyoto takes the proxy as a `SocketAddr`, so a hostname is reported rather
    /// than accepted and then failing obscurely.
    #[cfg(feature = "cbf")]
    #[test]
    fn test_cbf_backend_rejects_a_proxy_hostname() {
        let (cli, _temp_dir) = setup_wallet_with_args("cbf", &["--proxy", "tor.local:9050"]);

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "cbf backend needs --proxy as an ip:port address",
            ));
    }

    /// Kyoto's proxy carries no credentials, so `--proxy_auth` is reported rather
    /// than silently dropped.
    #[cfg(all(feature = "cbf", any(feature = "electrum", feature = "esplora")))]
    #[test]
    fn test_cbf_backend_rejects_proxy_auth() {
        let (cli, _temp_dir) = setup_wallet_with_args(
            "cbf",
            &["--proxy", "127.0.0.1:9050", "--proxy_auth", "user:password"],
        );

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "cbf backend does not support --proxy_auth",
            ));
    }

    /// Kyoto has no proxy-specific timeout knob, so `--timeout` is reported rather
    /// than silently dropped.
    #[cfg(all(feature = "cbf", any(feature = "electrum", feature = "esplora")))]
    #[test]
    fn test_cbf_backend_rejects_timeout() {
        let (cli, _temp_dir) =
            setup_wallet_with_args("cbf", &["--proxy", "127.0.0.1:9050", "--timeout", "30"]);

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "cbf backend does not support --timeout",
            ));
    }
}
