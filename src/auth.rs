use crate::{
    config::Config,
    storage::{Store, unix_now},
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::{HeaderMap, header};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

const COOKIE_NAME: &str = "sentinel_session";

#[derive(Clone)]
pub struct Auth {
    store: Store,
    bootstrap_path: PathBuf,
    session_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub token_hash: String,
    pub csrf: String,
}

impl Auth {
    pub fn new(config: &Config, store: Store) -> Self {
        Self {
            store,
            bootstrap_path: config.server.bootstrap_file.clone(),
            session_seconds: config.server.session_hours.clamp(1, 168) * 3600,
        }
    }
    pub fn bootstrap_path(&self) -> Option<PathBuf> {
        Some(self.bootstrap_path.clone())
    }
    pub fn is_configured(&self) -> anyhow::Result<bool> {
        self.store.has_account()
    }
    pub fn reset_password(&self) -> anyhow::Result<PathBuf> {
        self.store.reset_admin_account()?;
        let _ = fs::remove_file(&self.bootstrap_path);
        let _token = self.ensure_bootstrap_token()?;
        Ok(self.bootstrap_path.clone())
    }

    pub fn ensure_bootstrap_token(&self) -> anyhow::Result<String> {
        if self.store.has_account()? {
            let _ = fs::remove_file(&self.bootstrap_path);
            return Ok(String::new());
        }
        if let Ok(existing) = fs::read_to_string(&self.bootstrap_path) {
            let token = existing.trim().to_string();
            if !token.is_empty()
                && self
                    .store
                    .bootstrap_token_valid(&digest(&token), unix_now())?
            {
                return Ok(token);
            }
            fs::remove_file(&self.bootstrap_path)?;
        }
        if let Some(parent) = self.bootstrap_path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let token = random_hex(32)?;
        self.store
            .register_bootstrap_token(&digest(&token), unix_now())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.bootstrap_path)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(token)
    }

    pub async fn setup(
        &self,
        token: &str,
        password: &str,
    ) -> anyhow::Result<Option<(String, String, i64)>> {
        validate_password(password)?;
        if token.len() < 32
            || !self
                .store
                .bootstrap_token_valid(&digest(token), unix_now())?
        {
            return Ok(None);
        }
        let pass = password.to_owned();
        let hash = tokio::task::spawn_blocking(move || hash_password(&pass)).await??;
        if !self
            .store
            .create_admin_once(&digest(token), &hash, unix_now())?
        {
            return Ok(None);
        }
        let _ = fs::remove_file(&self.bootstrap_path);
        self.create_session()
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<(String, String, i64)>> {
        let Some(hash) = self.store.account_hash(username)? else {
            return Ok(None);
        };
        let pass = password.to_owned();
        let valid = tokio::task::spawn_blocking(move || verify_password(&pass, &hash)).await??;
        if !valid {
            return Ok(None);
        }
        self.create_session()
    }

    fn create_session(&self) -> anyhow::Result<Option<(String, String, i64)>> {
        let token = random_hex(32)?;
        let csrf = random_hex(32)?;
        let now = unix_now();
        let expires = now + self.session_seconds as i64;
        self.store
            .create_session(&digest(&token), &csrf, now, expires)?;
        Ok(Some((token, csrf, expires)))
    }

    pub fn session(&self, headers: &HeaderMap) -> anyhow::Result<Option<Session>> {
        let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        let Some(token) = cookie
            .split(';')
            .filter_map(|part| part.trim().split_once('='))
            .find(|(name, _)| *name == COOKIE_NAME)
            .map(|(_, value)| value)
        else {
            return Ok(None);
        };
        if token.len() > 128 {
            return Ok(None);
        }
        let token_hash = digest(token);
        let Some((csrf, expires_at)) = self.store.session(&token_hash, unix_now())? else {
            return Ok(None);
        };
        let _ = expires_at;
        Ok(Some(Session { token_hash, csrf }))
    }

    pub fn logout(&self, headers: &HeaderMap) -> anyhow::Result<()> {
        if let Some(s) = self.session(headers)? {
            self.store.delete_session(&s.token_hash)?;
        }
        Ok(())
    }
    pub fn cookie(token: &str, max_age: i64, secure: bool) -> String {
        format!(
            "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
            if secure { "; Secure" } else { "" }
        )
    }
}

pub fn validate_password(password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        password.len() >= 12,
        "password must contain at least 12 bytes"
    );
    anyhow::ensure!(password.len() <= 128, "password must not exceed 128 bytes");
    anyhow::ensure!(
        password.chars().any(char::is_alphabetic) && password.chars().any(|c| !c.is_alphanumeric()),
        "password must include a letter and a non-letter character"
    );
    Ok(())
}
fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())?
        .to_string())
}
fn verify_password(password: &str, encoded: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(encoded)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}
fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn random_hex(bytes: usize) -> anyhow::Result<String> {
    let mut buffer = vec![0_u8; bytes];
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")?
        .read_exact(&mut buffer)?;
    Ok(hex::encode(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_require_strength() {
        assert!(validate_password("correct horse battery!").is_ok());
        assert!(validate_password("short!").is_err());
        assert!(validate_password("abcdefghijklmnop").is_err());
    }
    #[tokio::test]
    async fn bootstrap_is_single_use() {
        let d = tempfile::tempdir().unwrap();
        let cfg = Config {
            server: crate::config::ServerConfig {
                bootstrap_file: d.path().join("token"),
                database_dir: d.path().to_path_buf(),
                ..Config::default().server
            },
            ..Config::default()
        };
        let store = Store::open(&d.path().join("db.sqlite")).unwrap();
        let a = Auth::new(&cfg, store);
        let token = a.ensure_bootstrap_token().unwrap();
        assert!(
            a.setup(&token, "correct horse battery!")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            a.setup(&token, "another correct password!")
                .await
                .unwrap()
                .is_none()
        );
        assert!(a.is_configured().unwrap());
    }
}
