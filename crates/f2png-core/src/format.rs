use crate::payload::MAGIC_V2;
use anyhow::Result;

pub const HEADER_FIXED_LEN: usize = 4 + 1 + 1 + 1 + 1 + 1 + 12 + 8 + 8;

#[derive(Debug)]
pub struct Header {
    pub bpc: u8,
    pub encrypted: bool,
    pub multi: bool,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub cipher_len: usize,
    pub plain_len: usize,
    pub header_size: usize,
}

pub fn build_header(
    bpc: u8,
    encrypted: bool,
    multi: bool,
    salt: &[u8],
    nonce: &[u8],
    cipher_len: usize,
    plain_len: usize,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_FIXED_LEN + salt.len());
    buf.extend_from_slice(&MAGIC_V2);
    buf.push(0x01); // version
    let mut flags = 0u8;
    if encrypted {
        flags |= 0x01;
    }
    if multi {
        flags |= 0x02;
    }
    buf.push(flags);
    buf.push(bpc);
    buf.push(0); // reserved
    buf.push(salt.len() as u8);
    buf.extend_from_slice(salt);
    // nonce 12 bytes
    let mut nonce_fixed = [0u8; 12];
    let n_copy = nonce.len().min(12);
    nonce_fixed[..n_copy].copy_from_slice(&nonce[..n_copy]);
    buf.extend_from_slice(&nonce_fixed);
    buf.extend_from_slice(&(plain_len as u64).to_be_bytes());
    buf.extend_from_slice(&(cipher_len as u64).to_be_bytes());
    buf
}

pub fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < HEADER_FIXED_LEN {
        anyhow::bail!("Buffer demasiado pequeno para header.");
    }
    if &buf[0..4] != MAGIC_V2 {
        anyhow::bail!("Magic inválido (esperava F2L2).");
    }
    let version = buf[4];
    if version != 0x01 {
        anyhow::bail!("Versão de header não suportada: {}", version);
    }
    let flags = buf[5];
    let bpc = buf[6];
    let salt_len = buf[8] as usize;
    let header_base = 9;
    let header_after_salt = header_base + salt_len + 12 + 8 + 8;
    if buf.len() < header_after_salt {
        anyhow::bail!("Header truncado.");
    }
    let salt = buf[header_base..header_base + salt_len].to_vec();
    let nonce_start = header_base + salt_len;
    let nonce = buf[nonce_start..nonce_start + 12].to_vec();
    let plain_len =
        u64::from_be_bytes(buf[nonce_start + 12..nonce_start + 20].try_into().unwrap()) as usize;
    let cipher_len =
        u64::from_be_bytes(buf[nonce_start + 20..nonce_start + 28].try_into().unwrap()) as usize;
    Ok(Header {
        bpc,
        encrypted: (flags & 0x01) != 0,
        multi: (flags & 0x02) != 0,
        salt,
        nonce,
        cipher_len,
        plain_len,
        header_size: header_after_salt,
    })
}
