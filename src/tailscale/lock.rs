use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};

use super::Error;

use crate::error;

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
        let mut cmd = cmd_base
            .arg("bash")
            .arg("-c")
            .arg("tailscale lock status --json")
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .map_err(Error::FetchLockStatus)?;

        let mut ts_out = cmd.stdout.take().unwrap();

        let mut ts_out_bytes = Vec::new();

        ts_out.read_to_end(&mut ts_out_bytes).map_err(Error::FetchLockStatus)?;
        
        let status = cmd.wait().map_err(Error::FetchLockStatus)?;
        let code = status.code();

        let code_str = match code {
            Some(c) => c.to_string(),
            None => "Unknown".to_string(),
        };

        if !status.success() {
            error(format!("Signing node failed with code: {}", code_str));
            return Err(Error::TailscaleSubprocess(code))
        }

        let ts_out_raw = std::str::from_utf8(&ts_out_bytes).map_err(Error::ReadSubprocessOutput)?;

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
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .status();
    
    let status = match cmd {
        Ok(s) => s,
        Err(e) => return Err(Error::SignNode(e)),
    };
    
    let code = status.code();
    
    let code_str = match code {
        Some(c) => c.to_string(),
        None => "Unknown".to_string(),
    };
    
    if !status.success() {
        error(format!("Signing node failed with code: {}", code_str));
        return Err(Error::TailscaleSubprocess(code))
    }
    
    Ok(())
}
