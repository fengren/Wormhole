use keyring::Entry;

const SERVICE_NAME: &str = "com.zhengwei.wormhole";

fn entry(config_id: &str, kind: &str) -> keyring::Result<Entry> {
    Entry::new(SERVICE_NAME, &format!("{config_id}:{kind}"))
}

pub fn set_password(config_id: &str, password: &str) -> anyhow::Result<()> {
    let e = entry(config_id, "password").map_err(|e| anyhow::anyhow!("{}", e))?;
    e.set_password(password)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}

pub fn get_password(config_id: &str) -> anyhow::Result<String> {
    let e = entry(config_id, "password").map_err(|e| anyhow::anyhow!("{}", e))?;
    e.get_password().map_err(|e| anyhow::anyhow!("{}", e))
}

pub fn set_key_passphrase(config_id: &str, passphrase: &str) -> anyhow::Result<()> {
    let e = entry(config_id, "keypass").map_err(|e| anyhow::anyhow!("{}", e))?;
    e.set_password(passphrase)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}

pub fn get_key_passphrase(config_id: &str) -> anyhow::Result<String> {
    let e = entry(config_id, "keypass").map_err(|e| anyhow::anyhow!("{}", e))?;
    e.get_password().map_err(|e| anyhow::anyhow!("{}", e))
}

pub fn delete_credentials(config_id: &str) {
    if let Ok(e) = entry(config_id, "password") {
        let _ = e.delete_credential();
    }
    if let Ok(e) = entry(config_id, "keypass") {
        let _ = e.delete_credential();
    }
}
