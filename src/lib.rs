use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::Rng;
use base64::Engine;
use sha2::{Sha256, Digest};

pub struct EncryptedData {
    pub encrypted: String,
    pub nonce: Vec<u8>,
}

pub fn create_key_from_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn encrypt_data(data: &str, key_data: &[u8]) -> Result<EncryptedData, String> {
    // Criar chave de 32 bytes
    let key = create_key_from_bytes(key_data);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    
    // Gerar nonce aleatório
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Criar cipher
    let cipher = Aes256Gcm::new(key);

    // Criptografar
    let encrypted = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(EncryptedData {
        encrypted: base64::engine::general_purpose::STANDARD.encode(encrypted),
        nonce: nonce_bytes.to_vec(),
    })
}

pub fn decrypt_data(encrypted: &str, nonce: &[u8], key_data: &[u8]) -> Result<String, String> {
    // Criar chave de 32 bytes
    let key = create_key_from_bytes(key_data);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    
    // Recriar nonce
    let nonce = Nonce::from_slice(nonce);
    
    // Recriar cipher
    let cipher = Aes256Gcm::new(key);
    
    // Descriptografar
    let encrypted = base64::engine::general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| e.to_string())?;
        
    let decrypted = cipher
        .decrypt(nonce, encrypted.as_ref())
        .map_err(|e| e.to_string())?;
        
    String::from_utf8(decrypted)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key_data = b"test_key_data_12345";
        let test_data = "Hello, World!";
        
        let encrypted = encrypt_data(test_data, key_data).unwrap();
        let decrypted = decrypt_data(&encrypted.encrypted, &encrypted.nonce, key_data).unwrap();
        
        assert_eq!(decrypted, test_data);
    }
}
