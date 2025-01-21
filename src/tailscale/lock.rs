use std::io::Read;
use serde::{Deserialize, Serialize};
use std::process::Command;

use super::Error;

const MULLVAD_NODE_SUFFIX: &str = ".mullvad.ts.net.";

#[derive(Debug, Serialize, Deserialize)]
pub struct LockStatus {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Head")]
    pub head: Vec<u32>,
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodeKeySigned")]
    pub node_key_signed: bool,
    #[serde(rename = "TrustedKeys")]
    pub trusted_keys: Vec<TrustedKey>,
    #[serde(rename = "VisiblePeers")]
    pub visible_peers: Vec<Peer>,
    #[serde(rename = "FilteredPeers")]
    pub filtered_peers: Vec<Peer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedKey {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Votes")]
    pub votes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Peer {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<String>,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
}

impl LockStatus {
    pub fn fetch_from_cli() -> Result<LockStatus, Error> {
        let mut cmd_base = Command::new("/usr/bin/env");
        let cmd = cmd_base
            .arg("bash")
            .arg("-c")
            .arg("tailscale lock status --json");

        let ts_out = cmd.output().map_err(Error::FetchLockStatus)?.stdout;

        let ts_out_raw = std::str::from_utf8(&ts_out).map_err(Error::ReadSubprocessOutput)?;

        let status = match serde_json::from_str::<LockStatus>(ts_out_raw) {
            Ok(o) => o,
            Err(e) => return Err(Error::ParseOutput(e)),
        };

        Ok(status)
    }

    /// Returns a list of node keys for Mullvad nodes (node_key, name)
    pub fn select_mullvad_nodes(&self, resign: bool) -> Vec<(String, String)> {
        // (node_key, name)
        let mut nodes: Vec<(String, String)> = vec![];

        for n in &self.filtered_peers {
            if n.name.ends_with(MULLVAD_NODE_SUFFIX) {
                nodes.push((n.node_key.clone(), n.name.clone()));
            }
        }
        
        if resign {
            for n in &self.visible_peers {
                if n.name.ends_with(MULLVAD_NODE_SUFFIX) {
                    nodes.push((n.node_key.clone(), n.name.clone()));
                }
            }
        }

        nodes
    }
}

pub fn sign_node(key: impl std::fmt::Display) -> Result<(), Error> {
    let mut cmd_base = Command::new("/usr/bin/env");
    let cmd = cmd_base
        .arg("bash")
        .arg("-c")
        .arg(format!("tailscale lock sign {}", key))
        .status();
    
    match cmd {
        Ok(_) => {},
        Err(e) => return Err(Error::SignNode(e)),
    }
    
    Ok(())
}
