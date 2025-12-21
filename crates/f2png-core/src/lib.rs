//! f2png-core - LSB steganography + strong crypto (Rust).
//!
//! PT: Nucleo com LSB, cifra opcional (Argon2id + ChaCha20-Poly1305) e modo container.
//! EN: Core engine with LSB, optional crypto, and container mode.
//!
//! Highlights:
//! - Single and multi-file payloads.
//! - Progress callbacks for CLI/GUI.
//! - Container split/join helpers for < 2 GiB parts.
//!
//! Docs: see `docs/USAGE.pt.md` and `docs/USAGE.en.md` in the repo.
pub mod container;
pub mod crypto;
pub mod format;
pub mod lsb;
pub mod payload;

use crate::crypto::StreamDecryptReader;
use crate::crypto::{STREAM_CHUNK, TAG_SIZE};
use crate::format::{build_header, parse_header};
use crate::lsb::{
    capacity_bytes, embed_lsb_parallel, BitStreamReader, BlobRef, ProgressCb, ProgressPhase,
    ProgressUpdate,
};
use crate::payload::{
    build_payload_multi_streaming, build_payload_single_streaming, parse_payload_streaming,
    PayloadFile,
};
use anyhow::Result;
use image::{DynamicImage, GenericImageView};
use memmap2::Mmap;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;

pub use crate::container::{
    is_container_png, join_container_png_parts_to_file, split_container_png_to_parts,
    unwrap_container_png_to_dir, wrap_single_file_container_png, wrap_single_file_container_png_parts,
};

#[derive(Clone, Debug)]
pub struct EncryptOptions {
    pub password: Option<String>,
    pub bpc: u8,
    pub allow_upscale: bool,
}

#[derive(Debug)]
pub struct EmbedResult {
    pub stego_path: PathBuf,
    pub out_width: u32,
    pub out_height: u32,
    pub encrypted: bool,
    pub file_count: usize,
}

#[derive(Debug)]
pub struct RevealResult {
    pub output_paths: Vec<PathBuf>,
    pub encrypted: bool,
    pub multi: bool,
}

fn estimate_cipher_len(plain_len: usize, encrypted: bool) -> usize {
    if !encrypted {
        return plain_len;
    }
    // chacha20poly1305 stream adds 1 tag per STREAM_CHUNK, plus a final tag.
    let tag_blocks = (plain_len / STREAM_CHUNK) + 1;
    plain_len.saturating_add(tag_blocks.saturating_mul(TAG_SIZE))
}

fn preflight_capacity(
    img: &DynamicImage,
    bpc: u8,
    allow_upscale: bool,
    encrypted: bool,
    plain_len: usize,
) -> Result<()> {
    let salt_est = if encrypted { 22usize } else { 0usize };
    let header_len_est = crate::format::HEADER_FIXED_LEN + salt_est;
    let cipher_len_est = estimate_cipher_len(plain_len, encrypted);
    let total_bytes_est = header_len_est + cipher_len_est;

    let cap = capacity_bytes(img, bpc);
    if total_bytes_est <= cap {
        return Ok(());
    }
    if !allow_upscale {
        anyhow::bail!(
            "Payload não cabe na imagem (cap ~{} bytes, necessário ~{} bytes). \
Usa uma capa maior, aumenta --bpc, ou ativa --allow-upscale.",
            cap,
            total_bytes_est
        );
    }

    let (w, h) = img.dimensions();
    let bits_per_pixel = 3u64 * (bpc as u64);
    let required_bits = (total_bytes_est as u64) * 8;
    let current_bits = (w as u64) * (h as u64) * bits_per_pixel;
    let scale = ((required_bits as f64 / current_bits as f64).sqrt() * 1.01).max(1.0);
    let new_w = ((w as f64) * scale).ceil() as u32;
    let new_h = ((h as f64) * scale).ceil() as u32;

    let max_pixels_default: u64 = 512_000_000;
    let max_pixels = std::env::var("F2PNG_MAX_PIXELS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(max_pixels_default);
    let pixels = (new_w as u64)
        .checked_mul(new_h as u64)
        .ok_or_else(|| anyhow::anyhow!("Dimensões de saída overflow."))?;
    if pixels > max_pixels {
        let gib = (pixels as f64 * 4.0) / (1024.0 * 1024.0 * 1024.0);
        anyhow::bail!(
            "Payload demasiado grande para esta capa: com bpc={} seria necessário upscale ~{}x{} ({} px, ~{:.2} GiB RGBA). \
Usa uma capa maior/mais alta resolução, aumenta --bpc, ou (com risco de OOM) define F2PNG_MAX_PIXELS para permitir.",
            bpc,
            new_w,
            new_h,
            pixels,
            gib
        );
    }

    Ok(())
}

fn open_image(path: &Path) -> Result<DynamicImage> {
    Ok(image::open(path)?)
}

fn extract_payload_to_temp(
    img: &DynamicImage,
    bpc: u8,
    progress: ProgressCb,
) -> Result<(NamedTempFile, crate::format::Header)> {
    let mut reader = BitStreamReader::new(img, bpc)?;
    let mut header_buf = Vec::with_capacity(crate::format::HEADER_FIXED_LEN + 32);
    let tmp = NamedTempFile::new()?;
    let mut writer = BufWriter::new(tmp.reopen()?);
    let mut bytes_written = 0usize;
    let mut target_bytes: Option<usize> = None;
    let mut header: Option<crate::format::Header> = None;
    let start = Instant::now();

    while target_bytes.map_or(true, |t| bytes_written < t) {
        let byte = reader
            .next_byte()
            .ok_or_else(|| anyhow::anyhow!("Buffer extraído truncado."))?;
        writer.write_all(&[byte])?;
        bytes_written += 1;

        if header.is_none() {
            header_buf.push(byte);
            if header_buf.len() >= 9 {
                let salt_len = header_buf[8] as usize;
                let header_len = crate::format::HEADER_FIXED_LEN + salt_len;
                if header_buf.len() >= header_len {
                    let h = parse_header(&header_buf)?;
                    target_bytes = Some(h.header_size + h.cipher_len);
                    header = Some(h);
                }
            }
        }

        if let (Some(total), Some(cb)) = (target_bytes, progress.as_deref()) {
            let done_bits = bytes_written * 8;
            let total_bits = total * 8;
            let percent = (done_bits as f64 / total_bits as f64 * 100.0).min(100.0) as f32;
            let elapsed = start.elapsed().as_secs_f64();
            let speed_mib_s = if elapsed > 0.0 {
                (done_bits as f64 / 8.0) / (1024.0 * 1024.0) / elapsed
            } else {
                0.0
            };
            let remaining_bits = total_bits.saturating_sub(done_bits);
            let eta = if speed_mib_s > 0.0 {
                Some((remaining_bits as f64 / 8.0) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Extract,
                percent,
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    }
    writer.flush()?;
    let header = header.ok_or_else(|| anyhow::anyhow!("Header não encontrado."))?;
    Ok((tmp, header))
}

fn decrypt_blob_to_payload(
    header: &crate::format::Header,
    blob: &NamedTempFile,
    password: Option<&str>,
) -> Result<PayloadFile> {
    let mut cipher_file = blob.reopen()?;
    cipher_file.seek(SeekFrom::Start(header.header_size as u64))?;
    let cipher_reader = cipher_file.take(header.cipher_len as u64);
    let out_tmp = NamedTempFile::new()?;
    let mut writer = BufWriter::new(out_tmp.reopen()?);

    let copied = if header.encrypted {
        let pw = password.ok_or_else(|| anyhow::anyhow!("Password requerida"))?;
        let mut decryptor = StreamDecryptReader::new(pw, &header.salt, &header.nonce, cipher_reader)?;
        std::io::copy(&mut decryptor, &mut writer)?
    } else {
        let mut reader = BufReader::new(cipher_reader);
        std::io::copy(&mut reader, &mut writer)?
    };
    writer.flush()?;
    if copied as usize != header.plain_len {
        anyhow::bail!(
            "Bytes plaintext ({}) não coincidem com esperado ({})",
            copied,
            header.plain_len
        );
    }
    Ok(PayloadFile {
        file: out_tmp,
        len: header.plain_len,
    })
}

pub fn embed_single_file(
    cover: &Path,
    input_file: &Path,
    output: &Path,
    opts: &EncryptOptions,
    progress: ProgressCb,
) -> Result<EmbedResult> {
    let img = open_image(cover)?;

    let in_size = fs::metadata(input_file).map(|m| m.len()).unwrap_or(0);
    let name_len = input_file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned().len())
        .unwrap_or_else(|| "restored.bin".len());
    let plain_len_est = 1usize + 2 + name_len + 8 + 32 + (in_size as usize);
    preflight_capacity(
        &img,
        opts.bpc,
        opts.allow_upscale,
        opts.password.is_some(),
        plain_len_est,
    )?;

    let start = Instant::now();
    let prep_weight = 20.0f32;
    let enc_weight = if opts.password.is_some() { 15.0f32 } else { 0.0f32 };
    let save_weight = 2.0f32;
    let embed_weight = 100.0f32 - prep_weight - enc_weight - save_weight;

    let prep_report = |copied: u64| {
        if let Some(cb) = progress.as_deref() {
            let frac = if in_size > 0 {
                (copied.min(in_size) as f32) / (in_size as f32)
            } else {
                0.0
            };
            let elapsed = start.elapsed().as_secs_f64();
            let speed_mib_s = if elapsed > 0.0 {
                (copied as f64) / (1024.0 * 1024.0) / elapsed
            } else {
                0.0
            };
            let eta = if speed_mib_s > 0.0 && in_size > copied {
                Some(((in_size - copied) as f64) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Prepare,
                percent: (frac * prep_weight).min(prep_weight),
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    };

    let PayloadFile { file, len } =
        build_payload_single_streaming(input_file, {
            if progress.is_some() {
                Some(&prep_report as &dyn Fn(u64))
            } else {
                None
            }
        })?;

    let enc_start = Instant::now();
    let enc_report = |done: u64| {
        if let Some(cb) = progress.as_deref() {
            let frac = if len > 0 {
                (done.min(len as u64) as f32) / (len as f32)
            } else {
                0.0
            };
            let elapsed = start.elapsed().as_secs_f64();
            let enc_elapsed = enc_start.elapsed().as_secs_f64();
            let speed_mib_s = if enc_elapsed > 0.0 {
                (done as f64) / (1024.0 * 1024.0) / enc_elapsed
            } else {
                0.0
            };
            let remaining = (len as u64).saturating_sub(done);
            let eta = if speed_mib_s > 0.0 {
                Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Encrypt,
                percent: prep_weight + (frac * enc_weight),
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    };

    let crypto = crate::crypto::encrypt_payload_stream(
        opts.password.as_deref(),
        file,
        len,
        if progress.is_some() && opts.password.is_some() {
            Some(&enc_report as &dyn Fn(u64))
        } else {
            None
        },
    )?;
    let header = build_header(
        opts.bpc,
        crypto.encrypted,
        false,
        &crypto.salt,
        &crypto.nonce,
        crypto.cipher_len,
        crypto.plain_len,
    );
    let map_file = crypto.file.reopen()?;
    let mmap = unsafe { Mmap::map(&map_file)? };
    let blob = BlobRef::new(&header, &mmap);

    let mapped_progress = progress.as_ref().map(|outer| {
        let outer = Arc::clone(outer);
        Arc::new(move |mut p: ProgressUpdate| {
            p.phase = ProgressPhase::Embed;
            p.percent = prep_weight + enc_weight + (p.percent * embed_weight / 100.0);
            outer(p);
        }) as Arc<dyn Fn(ProgressUpdate) + Send + Sync>
    });
    let stego = embed_lsb_parallel(img, blob, opts.bpc, opts.allow_upscale, mapped_progress)?;
    if let Some(cb) = progress.as_deref() {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: prep_weight + enc_weight + embed_weight,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    stego.save(output)?;
    if let Some(cb) = progress.as_deref() {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: 100.0,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    let (w, h) = stego.dimensions();
    Ok(EmbedResult {
        stego_path: output.to_path_buf(),
        out_width: w,
        out_height: h,
        encrypted: crypto.encrypted,
        file_count: 1,
    })
}

pub fn embed_multi(
    cover: &Path,
    inputs: &[PathBuf],
    output: &Path,
    opts: &EncryptOptions,
    progress: ProgressCb,
) -> Result<EmbedResult> {
    let img = open_image(cover)?;

    let mut plain_len_est = 1usize + 4;
    for p in inputs {
        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let name_len = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned().len())
            .unwrap_or_else(|| "restored.bin".len());
        plain_len_est = plain_len_est
            .saturating_add(2 + name_len + 8 + 32)
            .saturating_add(size as usize);
    }
    preflight_capacity(
        &img,
        opts.bpc,
        opts.allow_upscale,
        opts.password.is_some(),
        plain_len_est,
    )?;

    let start = Instant::now();
    let prep_weight = 20.0f32;
    let enc_weight = if opts.password.is_some() { 15.0f32 } else { 0.0f32 };
    let save_weight = 2.0f32;
    let embed_weight = 100.0f32 - prep_weight - enc_weight - save_weight;

    let total_in: u64 = inputs
        .iter()
        .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let prep_report = |copied: u64| {
        if let Some(cb) = progress.as_deref() {
            let frac = if total_in > 0 {
                (copied.min(total_in) as f32) / (total_in as f32)
            } else {
                0.0
            };
            let elapsed = start.elapsed().as_secs_f64();
            let speed_mib_s = if elapsed > 0.0 {
                (copied as f64) / (1024.0 * 1024.0) / elapsed
            } else {
                0.0
            };
            let eta = if speed_mib_s > 0.0 && total_in > copied {
                Some(((total_in - copied) as f64) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Prepare,
                percent: (frac * prep_weight).min(prep_weight),
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    };

    let PayloadFile { file, len } =
        build_payload_multi_streaming(inputs, {
            if progress.is_some() {
                Some(&prep_report as &dyn Fn(u64))
            } else {
                None
            }
        })?;

    let enc_start = Instant::now();
    let enc_report = |done: u64| {
        if let Some(cb) = progress.as_deref() {
            let frac = if len > 0 {
                (done.min(len as u64) as f32) / (len as f32)
            } else {
                0.0
            };
            let elapsed = start.elapsed().as_secs_f64();
            let enc_elapsed = enc_start.elapsed().as_secs_f64();
            let speed_mib_s = if enc_elapsed > 0.0 {
                (done as f64) / (1024.0 * 1024.0) / enc_elapsed
            } else {
                0.0
            };
            let remaining = (len as u64).saturating_sub(done);
            let eta = if speed_mib_s > 0.0 {
                Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Encrypt,
                percent: prep_weight + (frac * enc_weight),
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    };

    let crypto = crate::crypto::encrypt_payload_stream(
        opts.password.as_deref(),
        file,
        len,
        if progress.is_some() && opts.password.is_some() {
            Some(&enc_report as &dyn Fn(u64))
        } else {
            None
        },
    )?;
    let header = build_header(
        opts.bpc,
        crypto.encrypted,
        true,
        &crypto.salt,
        &crypto.nonce,
        crypto.cipher_len,
        crypto.plain_len,
    );
    let map_file = crypto.file.reopen()?;
    let mmap = unsafe { Mmap::map(&map_file)? };
    let blob = BlobRef::new(&header, &mmap);

    let mapped_progress = progress.as_ref().map(|outer| {
        let outer = Arc::clone(outer);
        Arc::new(move |mut p: ProgressUpdate| {
            p.phase = ProgressPhase::Embed;
            p.percent = prep_weight + enc_weight + (p.percent * embed_weight / 100.0);
            outer(p);
        }) as Arc<dyn Fn(ProgressUpdate) + Send + Sync>
    });
    let stego = embed_lsb_parallel(img, blob, opts.bpc, opts.allow_upscale, mapped_progress)?;
    if let Some(cb) = progress.as_deref() {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: prep_weight + enc_weight + embed_weight,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    stego.save(output)?;
    if let Some(cb) = progress.as_deref() {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: 100.0,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    let (w, h) = stego.dimensions();
    Ok(EmbedResult {
        stego_path: output.to_path_buf(),
        out_width: w,
        out_height: h,
        encrypted: crypto.encrypted,
        file_count: inputs.len(),
    })
}

pub fn reveal_to_dir(
    stego: &Path,
    output_dir: &Path,
    bpc: u8,
    password: Option<String>,
    progress: ProgressCb,
) -> Result<RevealResult> {
    fs::create_dir_all(output_dir)?;
    let img = open_image(stego)?;
    let (tmp, header) = extract_payload_to_temp(&img, bpc, progress)?;
    if header.bpc != bpc {
        anyhow::bail!(
            "BPC fornecido ({}) não coincide com o embutido ({})",
            bpc,
            header.bpc
        );
    }
    let mut cipher_file = tmp.reopen()?;
    cipher_file.seek(SeekFrom::Start(header.header_size as u64))?;
    let cipher_reader = cipher_file.take(header.cipher_len as u64);

    let outputs = if header.encrypted {
        let pw = password.ok_or_else(|| anyhow::anyhow!("Password requerida"))?;
        let decryptor =
            StreamDecryptReader::new(&pw, &header.salt, &header.nonce, cipher_reader)?;
        parse_payload_streaming(decryptor, output_dir)?
    } else {
        parse_payload_streaming(cipher_reader, output_dir)?
    };
    Ok(RevealResult {
        output_paths: outputs,
        encrypted: header.encrypted,
        multi: header.multi,
    })
}

pub fn swap_cover(
    stego: &Path,
    new_cover: &Path,
    output: &Path,
    decrypt_password: Option<String>,
    opts: &EncryptOptions,
) -> Result<EmbedResult> {
    let img_new = open_image(new_cover)?;
    // extrair payload criptografado do stego original
    let img_old = open_image(stego)?;
    let (blob_tmp, header) = extract_payload_to_temp(&img_old, opts.bpc, None)?;
    let payload_plain = decrypt_blob_to_payload(&header, &blob_tmp, decrypt_password.as_deref())?;

    // re-encriptar com opts.password
    let crypto = crate::crypto::encrypt_payload_stream(
        opts.password.as_deref(),
        payload_plain.file,
        payload_plain.len,
        None,
    )?;
    let new_header = build_header(
        opts.bpc,
        crypto.encrypted,
        header.multi,
        &crypto.salt,
        &crypto.nonce,
        crypto.cipher_len,
        crypto.plain_len,
    );
    let map_file = crypto.file.reopen()?;
    let mmap = unsafe { Mmap::map(&map_file)? };
    let blob = BlobRef::new(&new_header, &mmap);

    let stego_new = embed_lsb_parallel(img_new, blob, opts.bpc, opts.allow_upscale, None)?;
    stego_new.save(output)?;
    let (w, h) = stego_new.dimensions();
    Ok(EmbedResult {
        stego_path: output.to_path_buf(),
        out_width: w,
        out_height: h,
        encrypted: crypto.encrypted,
        file_count: 0,
    })
}

pub fn info_capacity(image: &Path, bpc: u8) -> Result<(u32, u32, usize)> {
    let img = open_image(image)?;
    let cap = capacity_bytes(&img, bpc);
    Ok((img.width(), img.height(), cap))
}
