use std::{env, fs, io::Write, net::SocketAddr, path::PathBuf, str::FromStr};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand_core::{OsRng, RngCore};

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_directory: PathBuf,
    pub image_directory: PathBuf,
    pub task_directory: PathBuf,
    pub static_directory: PathBuf,
    pub production: bool,
    pub master_key: [u8; 32],
    pub worker_concurrency: usize,
    pub support_email: Option<String>,
    pub support_wechat: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let server_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let production = env::var("LUMORA_ENV").is_ok_and(|value| value == "production");
        let data_directory = env::var_os("LUMORA_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| server_directory.join("data"));
        let image_directory = data_directory.join("images");
        let task_directory = data_directory.join("tasks");
        fs::create_dir_all(&image_directory)?;
        fs::create_dir_all(&task_directory)?;

        let bind = SocketAddr::from_str(
            &env::var("LUMORA_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into()),
        )?;
        let static_directory = env::var_os("LUMORA_STATIC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| server_directory.join("static"));
        let master_key = load_master_key(&data_directory, production)?;
        let worker_concurrency = env::var("LUMORA_WORKER_CONCURRENCY")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0 && *value <= 16)
            .unwrap_or(2);

        Ok(Self {
            bind,
            data_directory,
            image_directory,
            task_directory,
            static_directory,
            production,
            master_key,
            worker_concurrency,
            support_email: non_empty_env("LUMORA_SUPPORT_EMAIL"),
            support_wechat: non_empty_env("LUMORA_SUPPORT_WECHAT"),
        })
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn load_master_key(
    data_directory: &std::path::Path,
    production: bool,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let encoded = match env::var("LUMORA_MASTER_KEY") {
        Ok(value) => value,
        Err(_) if production => {
            return Err("production requires LUMORA_MASTER_KEY (base64-encoded 32 bytes)".into())
        }
        Err(_) => {
            let path = data_directory.join("master.key");
            if path.exists() {
                fs::read_to_string(path)?.trim().to_string()
            } else {
                let mut bytes = [0_u8; 32];
                OsRng.fill_bytes(&mut bytes);
                let encoded = BASE64.encode(bytes);
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(path)?;
                file.write_all(encoded.as_bytes())?;
                encoded
            }
        }
    };
    let decoded = BASE64.decode(encoded)?;
    decoded
        .try_into()
        .map_err(|_| "LUMORA_MASTER_KEY must decode to exactly 32 bytes".into())
}
