use std::io::Read;

use reqwest::Client;
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};
use argon2::Argon2;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Digest};
use aes::Aes256;
use cbc::Decryptor;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockDecryptMut};
use hmac::Hmac;

type HmacSha256 = Hmac<Sha256>;
// type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Debug, Deserialize)]
struct PreloginResponse {
    kdf: u32,
    kdf_iterations: Option<u32>,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    kdf_salt: String,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    access_token: String,
    Key: String,
}

#[derive(Debug, Deserialize)]
struct Cipher {
    #[serde(rename = "Type")]
    typ: u8,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Notes")]
    notes: Option<String>,
    #[serde(rename = "Login")]
    login: Option<Login>,
}

#[derive(Debug, Deserialize)]
struct Login {
    #[serde(rename = "Username")]
    username: Option<String>,
    #[serde(rename = "Password")]
    password: Option<String>,
}

fn base64_decode(s: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(s).unwrap()
}

fn derive_master_key(
    password: &str,
    email: &str,
    prelogin: &PreloginResponse,
) -> Vec<u8> {
    let salt = prelogin.kdf_salt.as_bytes();
    match prelogin.kdf {
        0 => {
            // PBKDF2
            let mut derived = vec![0u8; 32];
            let iterations = prelogin.kdf_iterations.unwrap_or(600_000);
            let secret = format!("{}{}", email.to_lowercase(), password);
            pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, iterations, &mut derived);
            derived
        }
        2 => {
            // Argon2id
            let memory = prelogin.kdf_memory.unwrap_or(64);
            let iterations = prelogin.kdf_iterations.unwrap_or(3);
            let parallelism = prelogin.kdf_parallelism.unwrap_or(4);
            let secret = format!("{}{}", email.to_lowercase(), password);
            let mut derived = vec![0u8; 32];
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(memory * 1024, iterations, parallelism, None).unwrap(),
            );
            argon2.hash_password_into(secret.as_bytes(), salt, &mut derived).unwrap();
            derived
        }
        _ => panic!("Unsupported KDF"),
    }
}

fn decrypt_aes256_cbc(enc: &str, key: &[u8]) -> Vec<u8> {
    let enc = enc.strip_prefix("2.").unwrap();
    let mut parts = enc.split('|');
    let iv: &[u8;16] = base64_decode(parts.next().unwrap());
    let ct = base64_decode(parts.next().unwrap());
    // let cipher = Aes256Cbc::new_from_slices(key, &iv).unwrap();

    let mut buf = enc.clone().as_bytes();
    let mut decryptor = Decryptor::<Aes256>::new(key.into(), &iv.into());

    decryptor.decrypt_padded_mut(&mut buf).unwrap().into()
    // cipher.decrypt_vec(&ct).unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CHANGE THESE:
    let email = "user@example.com";
    let password = "yourpassword";
    let server = "https://your-vaultwarden-server";

    let client = Client::new();

    // 1. Prelogin to get KDF config
    let prelogin: PreloginResponse = client
        .post(&format!("{}/accounts/prelogin", server))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await?
        .json()
        .await?;

    // 2. Derive master key
    let master_key = derive_master_key(password, email, &prelogin);

    // 3. Hash master key for authentication
    let master_key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&master_key);
        let res = hasher.finalize();
        hex::encode(res)
    };

    // 4. Authenticate (get session token and encrypted user key)
    let params = [
        ("grant_type", "password"),
        ("username", email),
        ("password", &master_key_hash),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "8"),
        ("deviceIdentifier", "vaultcommander"),
        ("deviceName", "VaultCommander"),
    ];
    let login: LoginResponse = client
        .post(&format!("{}/identity/connect/token", server))
        .form(&params)
        .send()
        .await?
        .json()
        .await?;

    // 5. Decrypt the user key
    let user_key = decrypt_aes256_cbc(&login.Key, &master_key);

    // 6. Fetch encrypted ciphers (vault items)
    let ciphers: Vec<Cipher> = client
        .get(&format!("{}/api/ciphers", server))
        .bearer_auth(&login.access_token)
        .send()
        .await?
        .json()
        .await?;

    // 7. Decrypt vault items (example for login type)
    for cipher in ciphers.iter().filter(|c| c.typ == 1) {
        if let Some(login) = &cipher.login {
            if let Some(enc_pw) = &login.password {
                let dec_pw = String::from_utf8(decrypt_aes256_cbc(enc_pw, &user_key)).unwrap();
                println!(
                    "Entry: {}\nUsername: {:?}\nPassword: {}\n",
                    cipher.name.as_deref().unwrap_or("No name"),
                    login.username,
                    dec_pw
                );
            }
        }
    }

    Ok(())
}
