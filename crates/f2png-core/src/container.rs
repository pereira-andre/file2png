use crate::crypto::{STREAM_CHUNK, TAG_SIZE};
use crate::lsb::{ProgressCb, ProgressPhase, ProgressUpdate};
use anyhow::Result;
use argon2::{password_hash::SaltString, Argon2};
use chacha20poly1305::{
    aead::{stream, KeyInit},
    ChaCha20Poly1305, Key,
};
use image::{ImageBuffer, Rgba};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

const CONTAINER_MAGIC: [u8; 4] = *b"F2C1";
const CONTAINER_FOOTER_MAGIC: [u8; 4] = *b"F2CF";
const CONTAINER_VERSION: u8 = 0x01;
const FOOTER_LEN: u64 = 4 + 1 + 8; // magic + version + header_start
const PART_SUFFIX_WIDTH: usize = 4;

fn format_part_header_name(base: &str, index: u32, total: u32) -> String {
    format!(
        "{}.part{:0width$}of{:0width$}",
        base,
        index,
        total,
        width = PART_SUFFIX_WIDTH
    )
}

fn parse_part_header_name(name: &str) -> Option<(String, u32, u32)> {
    let (base, suffix) = name.rsplit_once(".part")?;
    let (idx_str, total_str) = suffix.split_once("of")?;
    let index = idx_str.parse::<u32>().ok()?;
    let total = total_str.parse::<u32>().ok()?;
    if index == 0 || total == 0 {
        return None;
    }
    Some((base.to_string(), index, total))
}

fn cover_png_size(cover: Option<&Path>) -> Result<u64> {
    let tmp = tempfile::NamedTempFile::new()?;
    write_cover_png(cover, tmp.path())?;
    Ok(fs::metadata(tmp.path())?.len())
}

fn max_plain_len_for_limit(
    max_png_bytes: u64,
    cover_size: u64,
    name_len: usize,
    encrypted: bool,
    salt_len: usize,
) -> Result<u64> {
    let header_len = header_len(name_len, salt_len) as u64;
    let overhead = cover_size + header_len + FOOTER_LEN;
    if max_png_bytes <= overhead {
        anyhow::bail!("Limite demasiado baixo para a capa+overhead do container.");
    }
    let available = max_png_bytes - overhead;
    if !encrypted {
        return Ok(available);
    }
    let mut lo = 0u64;
    let mut hi = available;
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        if estimate_cipher_len_from_plain(mid, true) <= available {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    if lo == 0 {
        anyhow::bail!("Limite demasiado baixo para payload cifrado.");
    }
    Ok(lo)
}

fn decode_container_payload(
    file: &mut File,
    hdr: &ContainerHeader,
    data_start: u64,
    data_end: u64,
    password: Option<&str>,
    writer: &mut dyn Write,
    mut progress: Option<&mut dyn FnMut(u64, u64, f64, f64, ProgressPhase)>,
) -> Result<()> {
    let start = Instant::now();
    file.seek(SeekFrom::Start(data_start))?;
    let reader = file.take((data_end - data_start) as u64);
    let mut buf_reader = BufReader::new(reader);
    let mut hasher = Sha256::new();
    let mut processed_plain = 0u64;

    if hdr.encrypted {
        let pw = password.ok_or_else(|| anyhow::anyhow!("Password requerida"))?;
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(pw.as_bytes(), &hdr.salt, &mut key_bytes[..])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = Key::from_slice(&key_bytes[..]);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_arr7 = [0u8; 7];
        nonce_arr7.copy_from_slice(&hdr.nonce[..7]);
        let nonce_ga =
            *stream::Nonce::<ChaCha20Poly1305, stream::StreamBE32<ChaCha20Poly1305>>::from_slice(
                &nonce_arr7,
            );
        let mut decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce_ga);

        let mut cipher_buf = vec![0u8; STREAM_CHUNK + TAG_SIZE];
        loop {
            let mut filled = 0usize;
            while filled < cipher_buf.len() {
                let n = buf_reader.read(&mut cipher_buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let chunk = &cipher_buf[..filled];
            let plain = if filled == cipher_buf.len() {
                decryptor
                    .decrypt_next(chunk)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            } else {
                let res = decryptor
                    .decrypt_last(chunk)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                writer.write_all(&res)?;
                hasher.update(&res);
                processed_plain += res.len() as u64;
                if let Some(p) = progress.as_mut() {
                    let elapsed = start.elapsed().as_secs_f64();
                    let speed_mib_s = if elapsed > 0.0 {
                        (processed_plain as f64) / (1024.0 * 1024.0) / elapsed
                    } else {
                        0.0
                    };
                    p(
                        processed_plain,
                        hdr.plain_len,
                        elapsed,
                        speed_mib_s,
                        ProgressPhase::Decrypt,
                    );
                }
                break;
            };
            writer.write_all(&plain)?;
            hasher.update(&plain);
            processed_plain += plain.len() as u64;

            if let Some(p) = progress.as_mut() {
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    (processed_plain as f64) / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                p(
                    processed_plain,
                    hdr.plain_len,
                    elapsed,
                    speed_mib_s,
                    ProgressPhase::Decrypt,
                );
            }
        }
    } else {
        let mut buf = vec![0u8; STREAM_CHUNK];
        loop {
            let n = buf_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            processed_plain += n as u64;
            if let Some(p) = progress.as_mut() {
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    (processed_plain as f64) / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                p(
                    processed_plain,
                    hdr.plain_len,
                    elapsed,
                    speed_mib_s,
                    ProgressPhase::Parse,
                );
            }
        }
    }

    writer.flush()?;
    if processed_plain != hdr.plain_len {
        anyhow::bail!(
            "Tamanho plaintext não coincide: extraído {} vs esperado {}",
            processed_plain,
            hdr.plain_len
        );
    }
    let sha = hasher.finalize();
    if sha.as_slice() != hdr.sha256 {
        anyhow::bail!("SHA mismatch no container.");
    }
    Ok(())
}

fn write_cover_png(cover: Option<&Path>, out_png: &Path) -> Result<()> {
    if let Some(path) = cover {
        let img = image::open(path)?;
        img.save(out_png)?;
        return Ok(());
    }
    let img = ImageBuffer::from_pixel(512, 512, Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(out_png)?;
    Ok(())
}

fn estimate_cipher_len_from_plain(plain_len: u64, encrypted: bool) -> u64 {
    if !encrypted {
        return plain_len;
    }
    let chunk = STREAM_CHUNK as u64;
    let full_chunks = plain_len / chunk;
    let rem = plain_len % chunk;
    let tags = if plain_len == 0 {
        1
    } else if rem == 0 {
        // mesma convenção do core: um tag final vazio extra quando o tamanho é múltiplo do chunk
        full_chunks + 1
    } else {
        full_chunks + 1
    };
    plain_len + tags * (TAG_SIZE as u64)
}

#[derive(Debug)]
struct ContainerHeader {
    encrypted: bool,
    name: String,
    plain_len: u64,
    salt: Vec<u8>,
    nonce: [u8; 12],
    sha256: [u8; 32],
}

fn header_len(name_len: usize, salt_len: usize) -> usize {
    // magic(4) ver(1) flags(1) name_len(2) name(n) plain_len(8)
    // salt_len(1) salt(s) nonce(12) sha(32) cipher_len(8)
    4 + 1 + 1 + 2 + name_len + 8 + 1 + salt_len + 12 + 32 + 8
}

fn write_header_placeholder(
    writer: &mut BufWriter<File>,
    encrypted: bool,
    name: &str,
    plain_len: u64,
    salt: &[u8],
    nonce: &[u8; 12],
) -> Result<(u64, u64)> {
    // returns (sha_offset, cipher_len_offset) relative to file start
    let header_start = writer.stream_position()?;
    writer.write_all(&CONTAINER_MAGIC)?;
    writer.write_all(&[CONTAINER_VERSION])?;
    let flags = if encrypted { 0x01u8 } else { 0x00u8 };
    writer.write_all(&[flags])?;
    if name.len() > u16::MAX as usize {
        anyhow::bail!("Nome de ficheiro demasiado grande para embutir.");
    }
    writer.write_all(&(name.len() as u16).to_be_bytes())?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(&plain_len.to_be_bytes())?;
    if salt.len() > u8::MAX as usize {
        anyhow::bail!("Salt demasiado grande.");
    }
    writer.write_all(&[salt.len() as u8])?;
    writer.write_all(salt)?;
    writer.write_all(nonce)?;

    let sha_offset = writer.stream_position()?;
    writer.write_all(&[0u8; 32])?;
    let cipher_len_offset = writer.stream_position()?;
    writer.write_all(&0u64.to_be_bytes())?;

    let end = writer.stream_position()?;
    let expected = header_start + header_len(name.len(), salt.len()) as u64;
    if end != expected {
        anyhow::bail!(
            "Header size mismatch ({} vs {}).",
            end - header_start,
            expected - header_start
        );
    }
    Ok((sha_offset, cipher_len_offset))
}

fn write_footer(writer: &mut BufWriter<File>, header_start: u64) -> Result<()> {
    writer.write_all(&CONTAINER_FOOTER_MAGIC)?;
    writer.write_all(&[CONTAINER_VERSION])?;
    writer.write_all(&header_start.to_be_bytes())?;
    Ok(())
}

fn read_footer(file: &mut File) -> Result<u64> {
    let len = file.metadata()?.len();
    if len < FOOTER_LEN {
        anyhow::bail!("Não é um container (ficheiro demasiado pequeno).");
    }
    file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
    let mut buf = [0u8; FOOTER_LEN as usize];
    file.read_exact(&mut buf)?;
    if &buf[0..4] != CONTAINER_FOOTER_MAGIC {
        anyhow::bail!("Não é um container (footer magic ausente).");
    }
    if buf[4] != CONTAINER_VERSION {
        anyhow::bail!("Versão de container não suportada: {}", buf[4]);
    }
    let mut start_bytes = [0u8; 8];
    start_bytes.copy_from_slice(&buf[5..13]);
    let header_start = u64::from_be_bytes(start_bytes);
    if header_start >= len - FOOTER_LEN {
        anyhow::bail!("Footer inválido (header_start fora do ficheiro).");
    }
    Ok(header_start)
}

fn read_header(file: &mut File, header_start: u64) -> Result<(ContainerHeader, u64, u64)> {
    // returns (header, data_start, data_end_exclusive)
    file.seek(SeekFrom::Start(header_start))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != CONTAINER_MAGIC {
        anyhow::bail!("Header magic inválido.");
    }
    let mut v = [0u8; 1];
    file.read_exact(&mut v)?;
    if v[0] != CONTAINER_VERSION {
        anyhow::bail!("Versão de container não suportada: {}", v[0]);
    }
    let mut flags = [0u8; 1];
    file.read_exact(&mut flags)?;
    let encrypted = (flags[0] & 0x01) != 0;

    let mut name_len_buf = [0u8; 2];
    file.read_exact(&mut name_len_buf)?;
    let name_len = u16::from_be_bytes(name_len_buf) as usize;
    if name_len == 0 || name_len > 4096 {
        anyhow::bail!("Nome inválido no container.");
    }
    let mut name_bytes = vec![0u8; name_len];
    file.read_exact(&mut name_bytes)?;
    let name = String::from_utf8_lossy(&name_bytes).to_string();

    let mut plain_len_buf = [0u8; 8];
    file.read_exact(&mut plain_len_buf)?;
    let plain_len = u64::from_be_bytes(plain_len_buf);

    let mut salt_len_buf = [0u8; 1];
    file.read_exact(&mut salt_len_buf)?;
    let salt_len = salt_len_buf[0] as usize;
    let mut salt = vec![0u8; salt_len];
    file.read_exact(&mut salt)?;

    let mut nonce = [0u8; 12];
    file.read_exact(&mut nonce)?;

    let mut sha256 = [0u8; 32];
    file.read_exact(&mut sha256)?;

    let mut cipher_len_buf = [0u8; 8];
    file.read_exact(&mut cipher_len_buf)?;
    let cipher_len = u64::from_be_bytes(cipher_len_buf);

    let data_start = file.stream_position()?;
    let len = file.metadata()?.len();
    let data_end = len - FOOTER_LEN;
    if data_start >= data_end {
        anyhow::bail!("Container truncado (sem dados).");
    }
    if cipher_len == 0 || data_start + cipher_len > data_end {
        anyhow::bail!("Container truncado (cipher_len inválido).");
    }

    Ok((
        ContainerHeader {
            encrypted,
            name,
            plain_len,
            salt,
            nonce,
            sha256,
        },
        data_start,
        data_start + cipher_len,
    ))
}

pub fn is_container_png(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    read_footer(&mut f).is_ok()
}

fn wrap_single_file_container_png_impl(
    cover: Option<&Path>,
    infile: &Path,
    out_png: &Path,
    password: Option<&str>,
    name_override: Option<&str>,
    progress: ProgressCb,
) -> Result<()> {
    let start = Instant::now();
    let cb = progress.as_ref();
    if let Some(cb) = cb {
        cb(ProgressUpdate {
            phase: ProgressPhase::Prepare,
            percent: 0.0,
            elapsed: 0.0,
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    write_cover_png(cover, out_png)?;

    let header_start = fs::metadata(out_png)?.len();
    let file_len = fs::metadata(infile)?.len();
    let name = name_override
        .map(|s| s.to_string())
        .or_else(|| infile.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "restored.bin".into());

    let encrypted = password.is_some();
    let cipher_len_est = estimate_cipher_len_from_plain(file_len, encrypted);

    let mut out = OpenOptions::new().read(true).append(true).open(out_png)?;
    out.seek(SeekFrom::End(0))?;
    let mut writer = BufWriter::new(out);

    let (salt, nonce, key) = if let Some(pw) = password {
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_salt().as_ref().as_bytes().to_vec();
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(pw.as_bytes(), &salt_bytes, &mut key_bytes[..])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = *Key::from_slice(&key_bytes[..]);
        let mut nonce_arr7 = [0u8; 7];
        OsRng.fill_bytes(&mut nonce_arr7);
        let mut nonce12 = [0u8; 12];
        nonce12[..7].copy_from_slice(&nonce_arr7);
        (salt_bytes, nonce12, Some((key, nonce_arr7)))
    } else {
        (Vec::new(), [0u8; 12], None)
    };

    let (sha_off, cipher_len_off) =
        write_header_placeholder(&mut writer, encrypted, &name, file_len, &salt, &nonce)?;
    let data_start = writer.stream_position()?;

    let mut reader = BufReader::new(File::open(infile)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; STREAM_CHUNK];

    let mut processed = 0u64;
    let mut cipher_written = 0u64;
    if let Some((key, nonce_arr7)) = key {
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce_ga =
            *stream::Nonce::<ChaCha20Poly1305, stream::StreamBE32<ChaCha20Poly1305>>::from_slice(
                &nonce_arr7,
            );
        let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce_ga);
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                let tail = encryptor.encrypt_last(&[][..])?;
                writer.write_all(&tail)?;
                cipher_written += tail.len() as u64;
                break;
            }
            hasher.update(&buf[..n]);
            processed += n as u64;
            if n == STREAM_CHUNK {
                let out_chunk = encryptor.encrypt_next(&buf[..n])?;
                writer.write_all(&out_chunk)?;
                cipher_written += out_chunk.len() as u64;
            } else {
                let out_chunk = encryptor.encrypt_last(&buf[..n])?;
                writer.write_all(&out_chunk)?;
                cipher_written += out_chunk.len() as u64;
                break;
            }
            if let Some(cb) = cb {
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    (processed as f64) / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                let remaining = file_len.saturating_sub(processed);
                let eta = if speed_mib_s > 0.0 {
                    Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
                } else {
                    None
                };
                cb(ProgressUpdate {
                    phase: ProgressPhase::Encrypt,
                    percent: (processed as f32 / file_len.max(1) as f32 * 100.0).min(100.0),
                    elapsed,
                    eta,
                    speed_mib_s,
                });
            }
        }
    } else {
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            processed += n as u64;
            writer.write_all(&buf[..n])?;
            cipher_written += n as u64;
            if let Some(cb) = cb {
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    (processed as f64) / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                let remaining = file_len.saturating_sub(processed);
                let eta = if speed_mib_s > 0.0 {
                    Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
                } else {
                    None
                };
                cb(ProgressUpdate {
                    phase: ProgressPhase::Prepare,
                    percent: (processed as f32 / file_len.max(1) as f32 * 100.0).min(100.0),
                    elapsed,
                    eta,
                    speed_mib_s,
                });
            }
        }
    }

    // footer
    write_footer(&mut writer, header_start)?;
    writer.flush()?;

    // patch sha + cipher_len
    let sha = hasher.finalize();
    let mut sha_arr = [0u8; 32];
    sha_arr.copy_from_slice(&sha);

    let mut f = OpenOptions::new().read(true).write(true).open(out_png)?;
    f.seek(SeekFrom::Start(sha_off))?;
    f.write_all(&sha_arr)?;
    f.seek(SeekFrom::Start(cipher_len_off))?;
    f.write_all(&cipher_written.to_be_bytes())?;

    let _ = cipher_len_est;
    let expected = estimate_cipher_len_from_plain(file_len, encrypted);
    if encrypted && cipher_written != expected {
        anyhow::bail!(
            "cipher_len inesperado: escrito {} vs estimado {} (plain_len={})",
            cipher_written,
            expected,
            file_len
        );
    }

    if let Some(cb) = cb {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: 100.0,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }

    let end_pos = fs::metadata(out_png)?.len();
    if end_pos < data_start + cipher_written + FOOTER_LEN {
        anyhow::bail!("Container final inválido (tamanho inesperado).");
    }
    Ok(())
}

pub fn wrap_single_file_container_png(
    cover: Option<&Path>,
    infile: &Path,
    out_png: &Path,
    password: Option<&str>,
    progress: ProgressCb,
) -> Result<()> {
    wrap_single_file_container_png_impl(cover, infile, out_png, password, None, progress)
}

pub fn unwrap_container_png_to_dir(
    stego: &Path,
    outdir: &Path,
    password: Option<&str>,
    progress: ProgressCb,
) -> Result<PathBuf> {
    fs::create_dir_all(outdir)?;
    let start = Instant::now();
    let cb = progress.as_ref();

    let mut file = File::open(stego)?;
    let header_start = read_footer(&mut file)?;
    let (hdr, data_start, data_end) = read_header(&mut file, header_start)?;

    let out_name = hdr
        .name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("restored.bin");
    let mut out_path = outdir.to_path_buf();
    out_path.push(out_name);

    let mut out = BufWriter::new(File::create(&out_path)?);
    let mut progress_adapter = cb.map(|cb| {
        let cb = Arc::clone(cb);
        move |processed: u64, total: u64, elapsed: f64, speed_mib_s: f64, phase: ProgressPhase| {
            let remaining = total.saturating_sub(processed);
            let eta = if speed_mib_s > 0.0 {
                Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase,
                percent: (processed as f32 / total.max(1) as f32 * 100.0).min(100.0),
                elapsed,
                eta,
                speed_mib_s,
            });
        }
    });
    decode_container_payload(
        &mut file,
        &hdr,
        data_start,
        data_end,
        password,
        &mut out,
        progress_adapter
            .as_mut()
            .map(|f| f as &mut dyn FnMut(u64, u64, f64, f64, ProgressPhase)),
    )?;

    if let Some(cb) = cb {
        cb(ProgressUpdate {
            phase: ProgressPhase::Save,
            percent: 100.0,
            elapsed: start.elapsed().as_secs_f64(),
            eta: None,
            speed_mib_s: 0.0,
        });
    }
    Ok(out_path)
}

pub fn wrap_single_file_container_png_parts(
    cover: Option<&Path>,
    infile: &Path,
    out_dir: &Path,
    max_png_bytes: u64,
    password: Option<&str>,
    progress: ProgressCb,
) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(out_dir)?;
    let file_len = fs::metadata(infile)?.len();
    let base_name = infile
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "restored.bin".into());
    let out_prefix = infile
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());

    let encrypted = password.is_some();
    let salt_len = if encrypted {
        let salt = SaltString::generate(&mut OsRng);
        salt.as_salt().as_ref().as_bytes().len()
    } else {
        0
    };
    let name_len = format_part_header_name(&base_name, 1, 1).len();
    let cover_size = cover_png_size(cover)?;
    let max_plain =
        max_plain_len_for_limit(max_png_bytes, cover_size, name_len, encrypted, salt_len)?;
    let total_parts = if file_len == 0 {
        1
    } else {
        (file_len + max_plain - 1) / max_plain
    };
    if total_parts > 9_999 {
        anyhow::bail!("Ficheiro demasiado grande para {} partes.", 9_999);
    }

    let mut reader = BufReader::new(File::open(infile)?);
    let temp_dir = tempfile::tempdir()?;
    let mut outputs = Vec::new();
    let total_plain = file_len.max(1);
    let start = Instant::now();
    let cb = progress.as_ref().map(Arc::clone);

    let mut processed_base = 0u64;
    for idx in 1..=(total_parts as u32) {
        let remaining = file_len.saturating_sub(processed_base);
        let part_len = if file_len == 0 {
            0
        } else {
            remaining.min(max_plain)
        };
        let mut tmp = tempfile::NamedTempFile::new_in(temp_dir.path())?;
        let mut left = part_len;
        let mut buf = vec![0u8; STREAM_CHUNK];
        while left > 0 {
            let to_read = (left as usize).min(buf.len());
            let n = reader.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            tmp.write_all(&buf[..n])?;
            left -= n as u64;
        }
        tmp.flush()?;

        let out_name = format!(
            "{}_part{:0width$}.png",
            out_prefix,
            idx,
            width = PART_SUFFIX_WIDTH
        );
        let out_path = out_dir.join(out_name);
        let header_name = format_part_header_name(&base_name, idx, total_parts as u32);

        let part_cb: ProgressCb = cb.as_ref().map(|cb| {
            let cb = Arc::clone(cb);
            let start = start;
            let processed_base = processed_base;
            let part_len = part_len;
            Arc::new(move |p: ProgressUpdate| {
                let done = processed_base as f64 + (part_len as f64) * (p.percent as f64 / 100.0);
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    done / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                let done_u64 = done.round().min(total_plain as f64) as u64;
                let remaining = total_plain.saturating_sub(done_u64);
                let eta = if speed_mib_s > 0.0 {
                    Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
                } else {
                    None
                };
                cb(ProgressUpdate {
                    phase: p.phase,
                    percent: (done_u64 as f32 / total_plain as f32 * 100.0).min(100.0),
                    elapsed,
                    eta,
                    speed_mib_s,
                });
            }) as Arc<dyn Fn(ProgressUpdate) + Send + Sync>
        });

        wrap_single_file_container_png_impl(
            cover,
            tmp.path(),
            &out_path,
            password,
            Some(&header_name),
            part_cb,
        )?;
        let out_size = fs::metadata(&out_path)?.len();
        if out_size > max_png_bytes {
            anyhow::bail!(
                "Parte {} excede o limite ({} > {}).",
                idx,
                out_size,
                max_png_bytes
            );
        }
        outputs.push(out_path);
        processed_base += part_len;
    }

    Ok(outputs)
}

pub fn split_container_png_to_parts(
    stego: &Path,
    cover: Option<&Path>,
    out_dir: &Path,
    max_png_bytes: u64,
    password: Option<&str>,
    progress: ProgressCb,
) -> Result<Vec<PathBuf>> {
    let tmp_dir = tempfile::tempdir()?;
    let extracted = unwrap_container_png_to_dir(stego, tmp_dir.path(), password, progress.clone())?;
    wrap_single_file_container_png_parts(
        cover,
        &extracted,
        out_dir,
        max_png_bytes,
        password,
        progress,
    )
}

pub fn join_container_png_parts_to_file(
    parts: &[PathBuf],
    outfile: &Path,
    password: Option<&str>,
    progress: ProgressCb,
) -> Result<()> {
    if parts.is_empty() {
        anyhow::bail!("Sem partes para juntar.");
    }

    struct PartInfo {
        path: PathBuf,
        base: String,
        index: u32,
        total: u32,
        plain_len: u64,
    }

    let mut infos = Vec::new();
    for p in parts {
        let mut f = File::open(p)?;
        let header_start = read_footer(&mut f)?;
        let (hdr, _data_start, _data_end) = read_header(&mut f, header_start)?;
        let (base, index, total) = parse_part_header_name(&hdr.name)
            .ok_or_else(|| anyhow::anyhow!("Nome de parte inválido no container: {}", hdr.name))?;
        infos.push(PartInfo {
            path: p.clone(),
            base,
            index,
            total,
            plain_len: hdr.plain_len,
        });
    }

    let base = infos[0].base.clone();
    let total = infos[0].total;
    let mut seen = HashSet::new();
    for info in &infos {
        if info.base != base {
            anyhow::bail!("Partes de ficheiros diferentes (base não coincide).");
        }
        if info.total != total {
            anyhow::bail!("Total de partes inconsistente.");
        }
        if !seen.insert(info.index) {
            anyhow::bail!("Parte repetida: {}", info.index);
        }
    }
    if infos.len() != total as usize {
        anyhow::bail!(
            "Faltam partes: esperado {}, recebido {}.",
            total,
            infos.len()
        );
    }
    infos.sort_by_key(|i| i.index);

    let total_plain: u64 = infos.iter().map(|i| i.plain_len).sum();
    let start = Instant::now();
    let cb = progress.as_ref().map(Arc::clone);
    let mut out = BufWriter::new(File::create(outfile)?);
    let mut processed_base = 0u64;

    for info in infos {
        let mut f = File::open(&info.path)?;
        let header_start = read_footer(&mut f)?;
        let (hdr, data_start, data_end) = read_header(&mut f, header_start)?;

        let mut part_cb = cb.as_ref().map(|cb| {
            let cb = Arc::clone(cb);
            let start = start;
            let processed_base = processed_base;
            move |processed: u64, _total: u64, _elapsed: f64, _speed: f64, phase: ProgressPhase| {
                let done = processed_base.saturating_add(processed);
                let elapsed = start.elapsed().as_secs_f64();
                let speed_mib_s = if elapsed > 0.0 {
                    (done as f64) / (1024.0 * 1024.0) / elapsed
                } else {
                    0.0
                };
                let remaining = total_plain.saturating_sub(done);
                let eta = if speed_mib_s > 0.0 {
                    Some((remaining as f64) / (1024.0 * 1024.0) / speed_mib_s)
                } else {
                    None
                };
                cb(ProgressUpdate {
                    phase,
                    percent: (done as f32 / total_plain.max(1) as f32 * 100.0).min(100.0),
                    elapsed,
                    eta,
                    speed_mib_s,
                });
            }
        });

        decode_container_payload(
            &mut f,
            &hdr,
            data_start,
            data_end,
            password,
            &mut out,
            part_cb
                .as_mut()
                .map(|f| f as &mut dyn FnMut(u64, u64, f64, f64, ProgressPhase)),
        )?;
        processed_base = processed_base.saturating_add(hdr.plain_len);
    }
    out.flush()?;
    Ok(())
}
