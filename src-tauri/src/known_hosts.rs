use crate::config::{self, SshConfig};
use ssh2::{CheckResult, KnownHostFileKind, Session};

pub(crate) fn verify_known_host(session: &Session, config: &SshConfig) -> Result<(), String> {
    let Some((host_key, key_type)) = session.host_key() else {
        return Err("SSH server did not provide a host key.".into());
    };
    let mut known_hosts = session.known_hosts().map_err(|err| err.to_string())?;
    let known_hosts_path = config::app_config_dir().join("known_hosts");
    if known_hosts_path.exists() {
        known_hosts
            .read_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
            .map_err(|err| err.to_string())?;
    }

    match known_hosts.check_port(&config.host, config.port, host_key) {
        CheckResult::Match => Ok(()),
        CheckResult::NotFound => {
            if let Some(parent) = known_hosts_path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
            let host_name = known_host_name(&config.host, config.port);
            known_hosts
                .add(&host_name, host_key, &config.host, key_type.into())
                .map_err(|err| err.to_string())?;
            known_hosts
                .write_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
                .map_err(|err| err.to_string())
        }
        CheckResult::Mismatch => Err(
            "SSH host key mismatch in Wormhole known_hosts. Verify the server fingerprint before resetting this host key.".into(),
        ),
        CheckResult::Failure => Err("Could not verify SSH host key.".into()),
    }
}

pub(crate) fn reset_known_host_for_config(config: &SshConfig) -> Result<bool, String> {
    let known_hosts_path = config::app_config_dir().join("known_hosts");
    if !known_hosts_path.exists() {
        return Ok(false);
    }

    let target = known_host_name(&config.host, config.port);
    let contents = std::fs::read_to_string(&known_hosts_path).map_err(|err| err.to_string())?;
    let mut removed = false;
    let retained: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let remove = known_hosts_line_matches(line, &target);
            removed |= remove;
            !remove
        })
        .collect();

    if removed {
        let mut next = retained.join("\n");
        if !next.is_empty() {
            next.push('\n');
        }
        std::fs::write(&known_hosts_path, next).map_err(|err| err.to_string())?;
    }

    Ok(removed)
}

pub(crate) fn known_host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

pub(crate) fn known_hosts_line_matches(line: &str, target: &str) -> bool {
    let Some(hosts) = line.split_whitespace().next() else {
        return false;
    };

    hosts.split(',').any(|host| host == target)
}
