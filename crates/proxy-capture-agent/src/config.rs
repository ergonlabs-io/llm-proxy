use proxy_capture_spool::{
    EncryptionKey, SpoolConfig, DEFAULT_CACHE_BYTES, MAX_CACHE_BYTES, MIN_DISK_BYTES,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

fn default_cache_bytes() -> usize {
    DEFAULT_CACHE_BYTES
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub mode: String,
    pub socket_path: PathBuf,
    pub node_id: String,
    pub producers: Vec<Producer>,
    pub spool: Spool,
    pub active_key_id: String,
    pub keys: Vec<Key>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub producer_id: String,
    pub uid: u32,
    pub tenants: Vec<String>,
    /// May query the spool's counters and read back records of its own
    /// tenants. Unset means no: a grant that only submits cannot read.
    #[serde(default)]
    pub inspect: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spool {
    pub directory: PathBuf,
    pub max_record_bytes: usize,
    pub max_disk_bytes: u64,
    #[serde(default = "default_cache_bytes")]
    pub cache_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub key_id: String,
    pub key_file: PathBuf,
}

fn invalid(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("agent.{path}: invalid or unsupported value"),
    )
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?.take(131_073).read_to_end(&mut bytes)?;
        if bytes.len() > 131_072 {
            return Err(invalid("config: exceeds 128 KiB"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| invalid("config: malformed JSON"))?;
        check_fields(
            &value,
            &[
                "version",
                "mode",
                "socket_path",
                "node_id",
                "producers",
                "spool",
                "active_key_id",
                "keys",
            ],
            "",
        )?;
        check_fields(
            &value["spool"],
            &[
                "directory",
                "max_record_bytes",
                "max_disk_bytes",
                "cache_bytes",
            ],
            "spool",
        )?;
        for (name, fields) in [
            (
                "producers",
                &["producer_id", "uid", "tenants", "inspect"][..],
            ),
            ("keys", &["key_id", "key_file"][..]),
        ] {
            if let Some(entries) = value[name].as_array() {
                for (i, entry) in entries.iter().enumerate() {
                    check_fields(entry, fields, &format!("{name}[{i}]"))?;
                }
            }
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let config: Self = serde_path_to_error::deserialize(&mut deserializer)
            .map_err(|e| invalid(&e.path().to_string()))?;
        deserializer
            .end()
            .map_err(|_| invalid("config: trailing data"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid("version"));
        }
        if self.mode != "metadata_spool_only" {
            return Err(invalid("mode"));
        }
        if !self.socket_path.is_absolute() {
            return Err(invalid("socket_path"));
        }
        if self.node_id.is_empty()
            || self.node_id.len() > 128
            || self.node_id.chars().any(char::is_control)
        {
            return Err(invalid("node_id"));
        }
        if self.producers.is_empty() || self.producers.len() > 256 {
            return Err(invalid("producers"));
        }
        let mut uids = HashSet::new();
        let mut ids = HashSet::new();
        let mut tenants = 0;
        for (i, grant) in self.producers.iter().enumerate() {
            let prefix = format!("producers[{i}]");
            if grant.producer_id.is_empty()
                || grant.producer_id.len() > 128
                || !ids.insert(&grant.producer_id)
            {
                return Err(invalid(&format!("{prefix}.producer_id")));
            }
            if !uids.insert(grant.uid) {
                return Err(invalid(&format!("{prefix}.uid")));
            }
            if grant.tenants.is_empty() {
                return Err(invalid(&format!("{prefix}.tenants")));
            }
            let mut unique = HashSet::new();
            for (j, tenant) in grant.tenants.iter().enumerate() {
                if tenant.is_empty() || tenant.len() > 512 || !unique.insert(tenant) {
                    return Err(invalid(&format!("{prefix}.tenants[{j}]")));
                }
                tenants += 1;
                if tenants > 1024 {
                    return Err(invalid("producers: too many tenant grants"));
                }
            }
        }
        if self.keys.is_empty() || self.keys.len() > 16 {
            return Err(invalid("keys"));
        }
        let mut key_ids = HashSet::new();
        for (i, key) in self.keys.iter().enumerate() {
            if key.key_id.is_empty() || key.key_id.len() > 128 || !key_ids.insert(&key.key_id) {
                return Err(invalid(&format!("keys[{i}].key_id")));
            }
            if !key.key_file.is_absolute() {
                return Err(invalid(&format!("keys[{i}].key_file")));
            }
        }
        if !key_ids.contains(&self.active_key_id) {
            return Err(invalid("active_key_id"));
        }
        if !self.spool.directory.is_absolute() {
            return Err(invalid("spool.directory"));
        }
        if self.spool.max_record_bytes == 0
            || self.spool.max_record_bytes > proxy_capture_protocol::MAX_RECORD_BYTES
        {
            return Err(invalid("spool.max_record_bytes"));
        }
        if self.spool.max_disk_bytes < MIN_DISK_BYTES
            || self.spool.max_disk_bytes > 1_099_511_627_776
        {
            return Err(invalid("spool.max_disk_bytes"));
        }
        if self.spool.cache_bytes == 0 || self.spool.cache_bytes > MAX_CACHE_BYTES {
            return Err(invalid("spool.cache_bytes"));
        }
        self.spool_config().validate().map_err(|_| invalid("spool"))
    }

    pub fn spool_config(&self) -> SpoolConfig {
        SpoolConfig {
            directory: self.spool.directory.clone(),
            node_id: self.node_id.clone(),
            max_record_bytes: self.spool.max_record_bytes,
            max_disk_bytes: self.spool.max_disk_bytes,
            cache_bytes: self.spool.cache_bytes,
        }
    }

    pub fn load_keys(&self) -> io::Result<(EncryptionKey, Vec<EncryptionKey>)> {
        let mut active = None;
        let mut recovery = Vec::new();
        for (i, key) in self.keys.iter().enumerate() {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::symlink_metadata(&key.key_file)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(invalid(&format!(
                    "keys[{i}].key_file: requires private regular file"
                )));
            }
            let mut bytes = Vec::new();
            File::open(&key.key_file)?
                .take(33)
                .read_to_end(&mut bytes)?;
            let raw: [u8; 32] = bytes
                .try_into()
                .map_err(|_| invalid(&format!("keys[{i}].key_file: requires 32 bytes")))?;
            let loaded = EncryptionKey::new(&key.key_id, raw)
                .map_err(|_| invalid(&format!("keys[{i}].key_id")))?;
            if key.key_id == self.active_key_id {
                active = Some(loaded);
            } else {
                recovery.push(loaded);
            }
        }
        Ok((active.ok_or_else(|| invalid("active_key_id"))?, recovery))
    }
}

fn check_fields(value: &serde_json::Value, fields: &[&str], path: &str) -> io::Result<()> {
    if let Some(object) = value.as_object() {
        for key in object.keys() {
            if !fields.contains(&key.as_str()) {
                return Err(invalid(&if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                }));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> serde_json::Value {
        serde_json::json!({"version":1,"mode":"metadata_spool_only","socket_path":"/private/tmp/agent.sock","node_id":"node",
            "producers":[{"producer_id":"proxy","uid":1000,"tenants":["default"]}],
            "spool":{"directory":"/private/tmp/spool","max_record_bytes":4096,"max_disk_bytes":4194304},
            "active_key_id":"key","keys":[{"key_id":"key","key_file":"/private/tmp/key"}]})
    }
    #[test]
    fn numeric_bounds_and_ambiguous_grants_are_rejected() {
        let config: Config = serde_json::from_value(valid()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.spool.cache_bytes, DEFAULT_CACHE_BYTES);
        for (field, value) in [("max_record_bytes", 524289), ("cache_bytes", 16777217)] {
            let mut input = valid();
            input["spool"][field] = value.into();
            assert!(serde_json::from_value::<Config>(input)
                .unwrap()
                .validate()
                .unwrap_err()
                .to_string()
                .contains(field));
        }
        let mut input = valid();
        input["producers"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"producer_id":"other","uid":1000,"tenants":["default"]}));
        assert!(serde_json::from_value::<Config>(input)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("producers[1].uid"));
    }
    #[test]
    fn inspect_defaults_to_false_and_unknown_producer_fields_stay_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        std::fs::write(&path, valid().to_string()).unwrap();
        assert!(!Config::load(&path).unwrap().producers[0].inspect);
        let mut input = valid();
        input["producers"][0]["inspect"] = true.into();
        std::fs::write(&path, input.to_string()).unwrap();
        assert!(Config::load(&path).unwrap().producers[0].inspect);
        let mut input = valid();
        input["producers"][0]["inspect_all"] = true.into();
        std::fs::write(&path, input.to_string()).unwrap();
        assert!(Config::load(&path)
            .unwrap_err()
            .to_string()
            .contains("agent.producers[0].inspect_all"));
    }
    #[test]
    fn strict_config_reports_full_unknown_paths_and_rejects_trailing_data() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let mut input = valid();
        input["keys"][0]["inline_secret"] = "not allowed".into();
        std::fs::write(&path, input.to_string()).unwrap();
        assert!(Config::load(&path)
            .unwrap_err()
            .to_string()
            .contains("agent.keys[0].inline_secret"));
        std::fs::write(&path, format!("{} true", valid())).unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(&path, valid().to_string()).unwrap();
        Config::load(&path).unwrap();
    }
    #[test]
    fn removed_segment_fields_fail_with_full_spool_paths() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        for field in [
            "max_segment_bytes",
            "max_segments",
            "max_segment_age_seconds",
        ] {
            let mut input = valid();
            input["spool"][field] = 1.into();
            std::fs::write(&path, input.to_string()).unwrap();
            assert!(Config::load(&path)
                .unwrap_err()
                .to_string()
                .contains(&format!("agent.spool.{field}")));
        }
    }
    #[test]
    fn private_fixed_length_key_files_are_required() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let key = temp.path().join("key");
        let mut input = valid();
        input["keys"][0]["key_file"] = key.to_string_lossy().to_string().into();
        let config: Config = serde_json::from_value(input).unwrap();
        std::fs::write(&key, [7; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        config.load_keys().unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config.load_keys().is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&key, [7; 33]).unwrap();
        assert!(config.load_keys().is_err());
    }
}
