//! The SOCKS5 proxy options must actually reach the blockchain client.
//!
//! These tests stand two TCP listeners in for the chain server and the proxy, so
//! they need neither a real node nor a real SOCKS5 service: all that matters is
//! which port the connection arrives on.
#[cfg(any(feature = "electrum", feature = "esplora"))]
mod test_proxy {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    #[cfg(feature = "rpc")]
    use predicates::prelude::*;
    use serde_json::Value;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{Receiver, channel};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    static WALLET_NAME: &str = "proxy_test_wallet";

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

    fn connected(rx: &Receiver<()>) -> bool {
        rx.recv_timeout(Duration::from_secs(5)).is_ok()
    }

    /// As above, but for an arbitrary client type and url.
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

    /// A proxy the backend cannot honour is rejected, rather than ignored.
    #[cfg(feature = "rpc")]
    #[test]
    fn test_rpc_backend_rejects_a_proxy() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "wpkh"])
            .output()
            .expect("failed to generate descriptors");
        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("invalid JSON from descriptor");
        let public = &desc_values["public_descriptors"];

        cli.build_base_cmd()
            .arg("wallet")
            .arg("--wallet")
            .arg(WALLET_NAME)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(public["external"].as_str().unwrap())
            .arg("--int-descriptor")
            .arg(public["internal"].as_str().unwrap())
            .arg("--client-type")
            .arg("rpc")
            .arg("--database-type")
            .arg("sqlite")
            .arg("--url")
            .arg("127.0.0.1:18443")
            .arg("--proxy")
            .arg("127.0.0.1:9050")
            .assert()
            .success();

        sync_cmd(&cli)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "rpc backend does not support a SOCKS5 proxy",
            ));
    }
}
