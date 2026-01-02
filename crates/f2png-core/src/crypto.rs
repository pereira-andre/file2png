use anyhow::Result;
use argon2::{password_hash::SaltString, Argon2};
use chacha20poly1305::{
    aead::{stream, Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{BufReader, BufWriter, Read, Write};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub struct CryptoOutput {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted: bool,
}

pub struct CryptoStreamOutput {
    pub file: NamedTempFile,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted: bool,
    pub cipher_len: usize,
    pub plain_len: usize,
}

pub(crate) const STREAM_CHUNK: usize = 4 * 1024 * 1024;
pub(crate) const TAG_SIZE: usize = 16;
const STREAM_NONCE_LEN: usize = 7;
type StreamNonce = stream::Nonce<ChaCha20Poly1305, stream::StreamBE32<ChaCha20Poly1305>>;

pub fn encrypt_payload(password: Option<&str>, plaintext: &[u8]) -> Result<CryptoOutput> {
    if let Some(pw) = password {
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_salt().as_ref().as_bytes().to_vec();
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(pw.as_bytes(), &salt_bytes, &mut key_bytes[..])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = Key::from_slice(&key_bytes[..]);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)?;
        Ok(CryptoOutput {
            ciphertext,
            salt: salt_bytes,
            nonce,
            encrypted: true,
        })
    } else {
        Ok(CryptoOutput {
            ciphertext: plaintext.to_vec(),
            salt: Vec::new(),
            nonce: Vec::new(),
            encrypted: false,
        })
    }
}

pub fn encrypt_payload_stream(
    password: Option<&str>,
    payload: NamedTempFile,
    plain_len: usize,
    on_progress: Option<&dyn Fn(u64)>,
) -> Result<CryptoStreamOutput> {
    if let Some(pw) = password {
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_salt().as_ref().as_bytes().to_vec();
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(pw.as_bytes(), &salt_bytes, &mut key_bytes[..])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = Key::from_slice(&key_bytes[..]);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_arr = [0u8; STREAM_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_arr);
        let mut nonce_header = [0u8; 12];
        nonce_header[..STREAM_NONCE_LEN].copy_from_slice(&nonce_arr);
        let nonce_vec = nonce_header.to_vec();
        let nonce_ga = *StreamNonce::from_slice(&nonce_arr);

        let mut reader = BufReader::new(payload.reopen()?);
        let out_file = NamedTempFile::new()?;
        let mut writer = BufWriter::new(out_file.reopen()?);
        let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce_ga);

        let mut buf = vec![0u8; STREAM_CHUNK];
        let mut processed_plain = 0u64;
        let mut written = 0usize;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                let tail = encryptor.encrypt_last(&[][..])?;
                writer.write_all(&tail)?;
                written += tail.len();
                break;
            }
            if n == STREAM_CHUNK {
                let chunk = encryptor.encrypt_next(&buf[..n])?;
                writer.write_all(&chunk)?;
                written += chunk.len();
                processed_plain += n as u64;
                if let Some(cb) = on_progress {
                    cb(processed_plain);
                }
            } else {
                let chunk = encryptor.encrypt_last(&buf[..n])?;
                writer.write_all(&chunk)?;
                written += chunk.len();
                processed_plain += n as u64;
                if let Some(cb) = on_progress {
                    cb(processed_plain);
                }
                break;
            }
        }
        if let Some(cb) = on_progress {
            cb(plain_len as u64);
        }
        writer.flush()?;
        Ok(CryptoStreamOutput {
            file: out_file,
            salt: salt_bytes,
            nonce: nonce_vec,
            encrypted: true,
            cipher_len: written,
            plain_len,
        })
    } else {
        Ok(CryptoStreamOutput {
            file: payload,
            salt: Vec::new(),
            nonce: Vec::new(),
            encrypted: false,
            cipher_len: plain_len,
            plain_len,
        })
    }
}

pub fn decrypt_payload(
    password: Option<&str>,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    encrypted_flag: bool,
) -> Result<Vec<u8>> {
    if !encrypted_flag {
        return Ok(ciphertext.to_vec());
    }
    let pw = password.ok_or_else(|| anyhow::anyhow!("Password requerida"))?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(pw.as_bytes(), salt, &mut key_bytes[..])
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let key = Key::from_slice(&key_bytes[..]);
    let cipher = ChaCha20Poly1305::new(key);
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}

pub struct StreamDecryptReader<R: Read> {
    inner: Option<stream::DecryptorBE32<ChaCha20Poly1305>>,
    reader: BufReader<R>,
    cipher_buf: Vec<u8>,
    cipher_filled: usize,
    plain_buf: Vec<u8>,
    plain_pos: usize,
    finished: bool,
}

impl<R: Read> StreamDecryptReader<R> {
    pub fn new(password: &str, salt: &[u8], nonce: &[u8], reader: R) -> Result<Self> {
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes[..])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = Key::from_slice(&key_bytes[..]);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_arr = [0u8; STREAM_NONCE_LEN];
        let to_copy = STREAM_NONCE_LEN.min(nonce.len());
        nonce_arr[..to_copy].copy_from_slice(&nonce[..to_copy]);
        let nonce_ga = *StreamNonce::from_slice(&nonce_arr);
        Ok(Self {
            inner: Some(stream::DecryptorBE32::from_aead(cipher, &nonce_ga)),
            reader: BufReader::new(reader),
            cipher_buf: vec![0u8; STREAM_CHUNK + TAG_SIZE],
            cipher_filled: 0,
            plain_buf: Vec::with_capacity(STREAM_CHUNK),
            plain_pos: 0,
            finished: false,
        })
    }
}

impl<R: Read> Read for StreamDecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.plain_pos < self.plain_buf.len() {
            let available = self.plain_buf.len() - self.plain_pos;
            let n = available.min(out.len());
            out[..n].copy_from_slice(&self.plain_buf[self.plain_pos..self.plain_pos + n]);
            self.plain_pos += n;
            return Ok(n);
        }
        if self.finished {
            return Ok(0);
        }

        self.plain_buf.clear();
        self.plain_pos = 0;
        self.cipher_filled = 0;

        while self.cipher_filled < self.cipher_buf.len() {
            let n = self
                .reader
                .read(&mut self.cipher_buf[self.cipher_filled..])?;
            if n == 0 {
                break;
            }
            self.cipher_filled += n;
        }
        if self.cipher_filled == 0 {
            return Ok(0);
        }

        let chunk = &self.cipher_buf[..self.cipher_filled];
        let decrypted = if self.cipher_filled == self.cipher_buf.len() {
            if let Some(ref mut inner) = self.inner {
                inner
                    .decrypt_next(chunk)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            } else {
                return Ok(0);
            }
        } else {
            let inner = self.inner.take().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Decryptor finalizado")
            })?;
            let res = inner
                .decrypt_last(chunk)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            self.finished = true;
            res
        };
        self.plain_buf.extend_from_slice(&decrypted);
        self.read(out)
    }
}
