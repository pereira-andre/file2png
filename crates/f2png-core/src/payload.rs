use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

pub const MAGIC_V2: [u8; 4] = *b"F2L2";

#[derive(Debug)]
pub struct FileEntry {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PayloadFile {
    pub file: NamedTempFile,
    pub len: usize,
}

const BUF_SIZE: usize = 1024 * 1024;
const MAX_NAME_LEN: usize = 4096;
const MAX_FILES: usize = 100_000;

fn file_to_entry(path: &Path) -> Result<FileEntry> {
    let data = fs::read(path)?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "restored.bin".to_string());
    Ok(FileEntry { name, data })
}

pub fn build_payload_single(input_file: &Path) -> Result<Vec<u8>> {
    let entry = file_to_entry(input_file)?;
    let mut buf = Vec::with_capacity(1 + 2 + entry.name.len() + 8 + 32 + entry.data.len());
    buf.push(b'S');
    buf.extend_from_slice(&(entry.name.len() as u16).to_be_bytes());
    buf.extend_from_slice(entry.name.as_bytes());
    buf.extend_from_slice(&(entry.data.len() as u64).to_be_bytes());
    let file_sha = Sha256::digest(&entry.data);
    buf.extend_from_slice(&file_sha);
    buf.extend_from_slice(&entry.data);
    Ok(buf)
}

pub fn build_payload_multi(inputs: &[PathBuf]) -> Result<Vec<u8>> {
    let mut entries = Vec::with_capacity(inputs.len());
    for p in inputs {
        entries.push(file_to_entry(p)?);
    }
    let mut buf = Vec::new();
    buf.push(b'M');
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        buf.extend_from_slice(&(e.name.len() as u16).to_be_bytes());
        buf.extend_from_slice(e.name.as_bytes());
        buf.extend_from_slice(&(e.data.len() as u64).to_be_bytes());
        let file_sha = Sha256::digest(&e.data);
        buf.extend_from_slice(&file_sha);
        buf.extend_from_slice(&e.data);
    }
    Ok(buf)
}

pub fn parse_payload(plaintext: &[u8], outdir: &Path) -> Result<Vec<PathBuf>> {
    if plaintext.is_empty() {
        anyhow::bail!("Payload vazio.");
    }
    match plaintext[0] {
        b'S' => parse_single(plaintext, outdir),
        b'M' => parse_multi(plaintext, outdir),
        _ => anyhow::bail!("Tipo de payload desconhecido."),
    }
}

fn sanitize_filename(name: &str) -> String {
    let name = name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("restored.bin");
    let name = name.trim_matches(['.', ' ']);
    let name = if name.is_empty() {
        "restored.bin"
    } else {
        name
    };
    name.chars()
        .map(|c| match c {
            '\0' | '/' | '\\' => '_',
            _ => c,
        })
        .take(MAX_NAME_LEN)
        .collect()
}

fn parse_single(data: &[u8], outdir: &Path) -> Result<Vec<PathBuf>> {
    if data.len() < 1 + 2 + 8 + 32 {
        anyhow::bail!("Payload single truncado.");
    }
    let name_len = u16::from_be_bytes(data[1..3].try_into().unwrap()) as usize;
    if data.len() < 3 + name_len + 8 + 32 {
        anyhow::bail!("Payload single truncado (nome).");
    }
    let name = sanitize_filename(&String::from_utf8_lossy(&data[3..3 + name_len]));
    let size_start = 3 + name_len;
    let size_u64 = u64::from_be_bytes(data[size_start..size_start + 8].try_into().unwrap());
    let size = usize::try_from(size_u64)
        .map_err(|_| anyhow::anyhow!("Tamanho de ficheiro demasiado grande."))?;
    let sha_start = size_start + 8;
    let sha_expected = &data[sha_start..sha_start + 32];
    let content_start = sha_start + 32;
    if data.len() < content_start + size {
        anyhow::bail!("Payload single truncado (dados).");
    }
    let content = &data[content_start..content_start + size];
    let sha_real = Sha256::digest(content);
    if sha_real.as_slice() != sha_expected {
        anyhow::bail!("SHA mismatch no payload single.");
    }
    fs::create_dir_all(outdir)?;
    let mut path = outdir.to_path_buf();
    path.push(name);
    fs::write(&path, content)?;
    Ok(vec![path])
}

fn parse_multi(data: &[u8], outdir: &Path) -> Result<Vec<PathBuf>> {
    if data.len() < 1 + 4 {
        anyhow::bail!("Payload multi truncado.");
    }
    let mut idx = 1;
    let count = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
    idx += 4;
    if count > MAX_FILES {
        anyhow::bail!("Payload multi com demasiados ficheiros ({}).", count);
    }
    let mut outputs = Vec::new();
    fs::create_dir_all(outdir)?;
    for _ in 0..count {
        if data.len() < idx + 2 {
            anyhow::bail!("Payload multi truncado (nome).");
        }
        let name_len = u16::from_be_bytes(data[idx..idx + 2].try_into().unwrap()) as usize;
        idx += 2;
        if data.len() < idx + name_len + 8 + 32 {
            anyhow::bail!("Payload multi truncado (nome+meta).");
        }
        let name = sanitize_filename(&String::from_utf8_lossy(&data[idx..idx + name_len]));
        idx += name_len;
        let size_u64 = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
        let size = usize::try_from(size_u64)
            .map_err(|_| anyhow::anyhow!("Tamanho de ficheiro demasiado grande."))?;
        idx += 8;
        let sha_expected = &data[idx..idx + 32];
        idx += 32;
        if data.len() < idx + size {
            anyhow::bail!("Payload multi truncado (dados).");
        }
        let content = &data[idx..idx + size];
        idx += size;
        let sha_real = Sha256::digest(content);
        if sha_real.as_slice() != sha_expected {
            anyhow::bail!("SHA mismatch num ficheiro multi.");
        }
        let mut path = outdir.to_path_buf();
        path.push(name);
        fs::write(&path, content)?;
        outputs.push(path);
    }
    Ok(outputs)
}

fn create_temp_payload() -> Result<(NamedTempFile, BufWriter<File>)> {
    let tmp = NamedTempFile::new()?;
    let writer = BufWriter::new(tmp.reopen()?);
    Ok((tmp, writer))
}

pub fn build_payload_single_streaming(
    input_file: &Path,
    on_copied: Option<&dyn Fn(u64)>,
) -> Result<PayloadFile> {
    let size = fs::metadata(input_file)?.len();
    let name = input_file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "restored.bin".to_string());
    if name.len() > u16::MAX as usize {
        anyhow::bail!("Nome de ficheiro demasiado grande para embutir.");
    }

    let (tmp, mut writer) = create_temp_payload()?;
    writer.write_all(&[b'S'])?;
    writer.write_all(&(name.len() as u16).to_be_bytes())?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(&size.to_be_bytes())?;
    // SHA placeholder (patch later) para permitir 1 só pass sobre o ficheiro.
    let sha_pos = 1u64 + 2 + (name.len() as u64) + 8;
    writer.write_all(&[0u8; 32])?;

    let mut reader = BufReader::new(File::open(input_file)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];
    let mut copied = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        copied += n as u64;
        if let Some(cb) = on_copied {
            cb(copied);
        }
    }
    writer.flush()?;
    let sha = hasher.finalize();
    let file = writer.get_mut();
    file.flush()?;
    use std::io::Seek;
    use std::io::SeekFrom;
    file.seek(SeekFrom::Start(sha_pos))?;
    file.write_all(&sha)?;
    file.seek(SeekFrom::End(0))?;

    let total = 1 + 2 + name.len() + 8 + 32 + copied as usize;
    Ok(PayloadFile {
        file: tmp,
        len: total,
    })
}

pub fn build_payload_multi_streaming(
    inputs: &[PathBuf],
    on_copied: Option<&dyn Fn(u64)>,
) -> Result<PayloadFile> {
    let (tmp, mut writer) = create_temp_payload()?;
    writer.write_all(&[b'M'])?;
    writer.write_all(&(inputs.len() as u32).to_be_bytes())?;
    let mut total = 1 + 4;

    let mut copied_total = 0u64;
    let mut buf = vec![0u8; BUF_SIZE];
    for path in inputs {
        let size = fs::metadata(path)?.len();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "restored.bin".to_string());
        if name.len() > u16::MAX as usize {
            anyhow::bail!("Nome de ficheiro demasiado grande para embutir.");
        }

        writer.write_all(&(name.len() as u16).to_be_bytes())?;
        writer.write_all(name.as_bytes())?;
        writer.write_all(&size.to_be_bytes())?;
        total += 2 + name.len() + 8;

        // SHA placeholder (patch later)
        let sha_pos = total as u64;
        writer.write_all(&[0u8; 32])?;
        total += 32;

        let mut reader = BufReader::new(File::open(path)?);
        let mut hasher = Sha256::new();
        let mut copied = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            copied += n as u64;
            copied_total += n as u64;
            if let Some(cb) = on_copied {
                cb(copied_total);
            }
        }
        total += copied as usize;

        writer.flush()?;
        let sha = hasher.finalize();
        let file = writer.get_mut();
        file.flush()?;
        use std::io::Seek;
        use std::io::SeekFrom;
        file.seek(SeekFrom::Start(sha_pos))?;
        file.write_all(&sha)?;
        file.seek(SeekFrom::End(0))?;
    }
    writer.flush()?;
    Ok(PayloadFile {
        file: tmp,
        len: total,
    })
}

pub fn parse_payload_streaming<R: Read>(mut reader: R, outdir: &Path) -> Result<Vec<PathBuf>> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        b'S' => parse_single_stream(reader, outdir),
        b'M' => parse_multi_stream(reader, outdir),
        _ => anyhow::bail!("Tipo de payload desconhecido."),
    }
}

fn parse_single_stream<R: Read>(mut reader: R, outdir: &Path) -> Result<Vec<PathBuf>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf)?;
    let name_len = u16::from_be_bytes(len_buf) as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        anyhow::bail!("Nome inválido no payload (len={}).", name_len);
    }
    let mut name_bytes = vec![0u8; name_len];
    reader.read_exact(&mut name_bytes)?;
    let mut size_buf = [0u8; 8];
    reader.read_exact(&mut size_buf)?;
    let size_u64 = u64::from_be_bytes(size_buf);
    let size = usize::try_from(size_u64)
        .map_err(|_| anyhow::anyhow!("Tamanho de ficheiro demasiado grande."))?;
    let mut sha_buf = [0u8; 32];
    reader.read_exact(&mut sha_buf)?;

    fs::create_dir_all(outdir)?;
    let mut path = outdir.to_path_buf();
    path.push(sanitize_filename(&String::from_utf8_lossy(&name_bytes)));
    let mut out = BufWriter::new(File::create(&path)?);
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buf = vec![0u8; BUF_SIZE];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        reader.read_exact(&mut buf[..to_read])?;
        out.write_all(&buf[..to_read])?;
        hasher.update(&buf[..to_read]);
        remaining -= to_read;
    }
    out.flush()?;
    let sha_real = hasher.finalize();
    if sha_real.as_slice() != sha_buf {
        anyhow::bail!("SHA mismatch no payload single.");
    }
    Ok(vec![path])
}

fn parse_multi_stream<R: Read>(mut reader: R, outdir: &Path) -> Result<Vec<PathBuf>> {
    let mut count_buf = [0u8; 4];
    reader.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;
    if count > MAX_FILES {
        anyhow::bail!("Payload multi com demasiados ficheiros ({}).", count);
    }
    let mut outputs = Vec::new();
    fs::create_dir_all(outdir)?;

    for _ in 0..count {
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)?;
        let name_len = u16::from_be_bytes(len_buf) as usize;
        if name_len == 0 || name_len > MAX_NAME_LEN {
            anyhow::bail!("Nome inválido no payload (len={}).", name_len);
        }
        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;

        let mut size_buf = [0u8; 8];
        reader.read_exact(&mut size_buf)?;
        let size_u64 = u64::from_be_bytes(size_buf);
        let size = usize::try_from(size_u64)
            .map_err(|_| anyhow::anyhow!("Tamanho de ficheiro demasiado grande."))?;

        let mut sha_buf = [0u8; 32];
        reader.read_exact(&mut sha_buf)?;

        let mut path = outdir.to_path_buf();
        path.push(sanitize_filename(&String::from_utf8_lossy(&name_bytes)));
        let mut out = BufWriter::new(File::create(&path)?);
        let mut hasher = Sha256::new();
        let mut remaining = size;
        let mut buf = vec![0u8; BUF_SIZE];
        while remaining > 0 {
            let to_read = remaining.min(buf.len());
            reader.read_exact(&mut buf[..to_read])?;
            out.write_all(&buf[..to_read])?;
            hasher.update(&buf[..to_read]);
            remaining -= to_read;
        }
        out.flush()?;
        let sha_real = hasher.finalize();
        if sha_real.as_slice() != sha_buf {
            anyhow::bail!("SHA mismatch num ficheiro multi.");
        }
        outputs.push(path);
    }
    Ok(outputs)
}
