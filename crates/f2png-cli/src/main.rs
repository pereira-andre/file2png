//! f2png-cli - Command-line interface for f2png.
//!
//! PT: Usa `cargo run -p f2png-cli -- --help` para ver comandos.
//! EN: Run `cargo run -p f2png-cli -- --help` for usage.
mod help;

use anyhow::Result;
use clap::{Parser, Subcommand};
use f2png_core::{
    embed_multi, embed_single_file, info_capacity,
    lsb::{ProgressPhase, ProgressUpdate},
    join_container_png_parts_to_file, reveal_to_dir, split_container_png_to_parts, swap_cover,
    unwrap_container_png_to_dir, wrap_single_file_container_png, wrap_single_file_container_png_parts,
    EncryptOptions,
};
use image::{ImageBuffer, Rgba};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

fn bar(percent: f32) -> String {
    let slots = 20;
    let filled = ((percent / 100.0) * slots as f32).round() as usize;
    let filled = filled.min(slots);
    let mut s = String::new();
    for _ in 0..filled {
        s.push('#');
    }
    for _ in filled..slots {
        s.push('-');
    }
    s
}

fn phase_tag(p: ProgressPhase) -> &'static str {
    match p {
        ProgressPhase::Prepare => "PREP",
        ProgressPhase::Encrypt => "ENC",
        ProgressPhase::Embed => "LSB",
        ProgressPhase::Save => "SAVE",
        ProgressPhase::Extract => "EXT",
        ProgressPhase::Decrypt => "DEC",
        ProgressPhase::Parse => "PARSE",
    }
}

fn format_eta(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--".into();
    }
    let total = secs.round() as u64;
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    if days > 0 {
        format!("{}d {:02}h", days, hours)
    } else if hours > 0 {
        format!("{}h {:02}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m {:02}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn print_progress(prefix: &str, p: &ProgressUpdate) {
    let eta = p
        .eta
        .map(format_eta)
        .unwrap_or_else(|| "--".into());
    eprint!(
        "\r{} {:<5} [{:<20}] {:5.1}% | {:6.2} MiB/s | ETA {}",
        prefix,
        phase_tag(p.phase),
        bar(p.percent),
        p.percent,
        p.speed_mib_s,
        eta
    );
    if p.percent >= 99.9 {
        eprintln!();
    }
}

#[derive(Parser)]
#[command(name = "f2png", about = "LSB + cifra forte em Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Embed {
        cover: PathBuf,
        infile: PathBuf,
        outfile: PathBuf,
        #[arg(long, default_value_t = 2)]
        bpc: u8,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = true)]
        allow_upscale: bool,
    },
    EmbedMulti {
        cover: PathBuf,
        outfile: PathBuf,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        bpc: u8,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = true)]
        allow_upscale: bool,
    },
    Reveal {
        stego: PathBuf,
        #[arg(long)]
        outdir: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = 2)]
        bpc: u8,
    },
    /// Container: guarda 1 ficheiro grande anexado ao PNG (não usa LSB).
    ContainerEmbed {
        cover: PathBuf,
        infile: PathBuf,
        outfile: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Container: divide um ficheiro grande em vários PNGs (< limite).
    ContainerEmbedSplit {
        cover: PathBuf,
        infile: PathBuf,
        outdir: PathBuf,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_bytes: u64,
        #[arg(long)]
        max_gib: Option<u64>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Container: extrai o ficheiro anexado ao PNG.
    ContainerReveal {
        stego: PathBuf,
        #[arg(long)]
        outdir: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Container: separa um PNG container em várias partes.
    ContainerSplit {
        stego: PathBuf,
        cover: PathBuf,
        outdir: PathBuf,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_bytes: u64,
        #[arg(long)]
        max_gib: Option<u64>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Container: junta partes em um único ficheiro.
    ContainerJoin {
        outfile: PathBuf,
        #[arg(required = false)]
        parts: Vec<PathBuf>,
        #[arg(long)]
        indir: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
    },
    SwapCover {
        stego: PathBuf,
        new_cover: PathBuf,
        outfile: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = 2)]
        bpc: u8,
        #[arg(long, default_value_t = true)]
        allow_upscale: bool,
    },
    Info {
        image: PathBuf,
        #[arg(long, default_value_t = 2)]
        bpc: u8,
    },
    /// Mostrar ajuda detalhada por tópico (para além do --help padrão).
    Topic { topic: Option<String> },
    /// Executa um benchmark (embed) e gera tabela de estimativas.
    Bench {
        /// Tamanho do ficheiro de teste (bytes)
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        size: u64,
        /// Bits por canal
        #[arg(long, default_value_t = 2)]
        bpc: u8,
        /// Caminho do ficheiro de saída para a tabela
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Benchmark container (embed) e tabela de estimativas.
    BenchContainerEmbed {
        /// Tamanho do ficheiro de teste (bytes)
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        size: u64,
        /// Password opcional (para testar cifra)
        #[arg(long)]
        password: Option<String>,
        /// Caminho do ficheiro de saída para a tabela
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Benchmark container (reveal) e tabela de estimativas.
    BenchContainerReveal {
        /// Tamanho do ficheiro de teste (bytes)
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        size: u64,
        /// Password opcional (para testar cifra)
        #[arg(long)]
        password: Option<String>,
        /// Caminho do ficheiro de saída para a tabela
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn fmt_size(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for u in units {
        if size < 1024.0 || u == "TiB" {
            return format!("{:.2} {}", size, u);
        }
        size /= 1024.0;
    }
    format!("{:.2} TiB", size)
}

fn fmt_time(seconds: f64) -> String {
    if seconds < 1.0 {
        return format!("{:.3} s", seconds);
    }
    if seconds < 60.0 {
        return format!("{:.2} s", seconds);
    }
    let mut s = seconds.round() as u64;
    let m = s / 60;
    s %= 60;
    if m < 60 {
        return format!("{} min {:02} s", m, s);
    }
    let h = m / 60;
    let m = m % 60;
    if h < 24 {
        return format!("{} h {:02} min", h, m);
    }
    let d = h / 24;
    let h = h % 24;
    format!("{} d {:02} h", d, h)
}

fn size_list() -> Vec<u64> {
    let mut sizes = Vec::new();
    for k in [1u64, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
        sizes.push(k * 1024);
    }
    for m in [1u64, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
        sizes.push(m * 1024 * 1024);
    }
    for g in [1u64, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
        sizes.push(g * 1024 * 1024 * 1024);
    }
    sizes.push(1u64 << 40); // 1 TiB
    sizes.sort_unstable();
    sizes
}

fn run_benchmark(size: u64, bpc: u8) -> Result<(f64, f64)> {
    let dir = tempdir()?;
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("bench.bin");
    let stego = dir.path().join("bench.png");

    // cria capa 1024x1024 cinzenta
    let img = ImageBuffer::from_pixel(1024, 1024, Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(&cover)?;

    // ficheiro de teste
    std::fs::write(&infile, vec![0u8; size as usize])?;

    let opts = EncryptOptions {
        password: None,
        bpc,
        allow_upscale: true,
    };
    let t0 = Instant::now();
    let _ = embed_single_file(&cover, &infile, &stego, &opts, None)?;
    let dt = t0.elapsed().as_secs_f64();
    let mib_s = if dt > 0.0 {
        (size as f64) / (1024.0 * 1024.0) / dt
    } else {
        0.0
    };
    Ok((dt, mib_s))
}

fn run_container_embed_benchmark(size: u64, password: Option<&str>) -> Result<(f64, f64)> {
    let dir = tempdir()?;
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("bench.bin");
    let stego = dir.path().join("bench.png");

    let img = ImageBuffer::from_pixel(1024, 1024, Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(&cover)?;
    std::fs::write(&infile, vec![0u8; size as usize])?;

    let t0 = Instant::now();
    wrap_single_file_container_png(Some(&cover), &infile, &stego, password, None)?;
    let dt = t0.elapsed().as_secs_f64();
    let mib_s = if dt > 0.0 {
        (size as f64) / (1024.0 * 1024.0) / dt
    } else {
        0.0
    };
    Ok((dt, mib_s))
}

fn run_container_reveal_benchmark(size: u64, password: Option<&str>) -> Result<(f64, f64)> {
    let dir = tempdir()?;
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("bench.bin");
    let stego = dir.path().join("bench.png");
    let outdir = dir.path().join("out");

    let img = ImageBuffer::from_pixel(1024, 1024, Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(&cover)?;
    std::fs::write(&infile, vec![0u8; size as usize])?;
    wrap_single_file_container_png(Some(&cover), &infile, &stego, password, None)?;

    let t0 = Instant::now();
    let _ = unwrap_container_png_to_dir(&stego, &outdir, password, None)?;
    let dt = t0.elapsed().as_secs_f64();
    let mib_s = if dt > 0.0 {
        (size as f64) / (1024.0 * 1024.0) / dt
    } else {
        0.0
    };
    Ok((dt, mib_s))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Embed {
            cover,
            infile,
            outfile,
            bpc,
            password,
            allow_upscale,
        } => {
            let opts = EncryptOptions {
                password,
                bpc,
                allow_upscale,
            };
            let size = std::fs::metadata(&infile)?.len() as f64;
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("EMBED", &p));
            embed_single_file(&cover, &infile, &outfile, &opts, Some(cb))?;
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                size / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] stego em {:?} | tempo {:.2}s | {:.2} MiB/s",
                outfile, dt, mbps
            );
        }
        Commands::EmbedMulti {
            cover,
            outfile,
            inputs,
            bpc,
            password,
            allow_upscale,
        } => {
            let opts = EncryptOptions {
                password,
                bpc,
                allow_upscale,
            };
            let total: f64 = inputs
                .iter()
                .map(|p| std::fs::metadata(p).map(|m| m.len() as f64).unwrap_or(0.0))
                .sum();
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("EMBED", &p));
            embed_multi(&cover, &inputs, &outfile, &opts, Some(cb))?;
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                total / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] stego em {:?} | tempo {:.2}s | {:.2} MiB/s",
                outfile, dt, mbps
            );
        }
        Commands::Reveal {
            stego,
            outdir,
            password,
            bpc,
        } => {
            let out = outdir.unwrap_or_else(|| stego.with_extension("out"));
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("REVEAL", &p));
            let res = reveal_to_dir(&stego, &out, bpc, password, Some(cb))?;
            let mut total: f64 = 0.0;
            for p in &res.output_paths {
                if let Ok(m) = std::fs::metadata(p) {
                    total += m.len() as f64;
                }
            }
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                total / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] {} ficheiro(s) extraído(s) para {:?} (encrypted={}) | tempo {:.2}s | {:.2} MiB/s",
                res.output_paths.len(),
                out,
                res.encrypted,
                dt,
                mbps
            );
        }
        Commands::ContainerEmbed {
            cover,
            infile,
            outfile,
            password,
        } => {
            let size = std::fs::metadata(&infile)?.len() as f64;
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("CONT", &p));
            wrap_single_file_container_png(
                Some(&cover),
                &infile,
                &outfile,
                password.as_deref(),
                Some(cb),
            )?;
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                size / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] container em {:?} | tempo {:.2}s | {:.2} MiB/s",
                outfile, dt, mbps
            );
        }
        Commands::ContainerEmbedSplit {
            cover,
            infile,
            outdir,
            max_bytes,
            max_gib,
            password,
        } => {
            let size = std::fs::metadata(&infile)?.len() as f64;
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("CONT", &p));
            let max_bytes = max_gib
                .map(|g| g.saturating_mul(1024 * 1024 * 1024))
                .unwrap_or(max_bytes);
            let parts = wrap_single_file_container_png_parts(
                Some(&cover),
                &infile,
                &outdir,
                max_bytes,
                password.as_deref(),
                Some(cb),
            )?;
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                size / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] {} partes em {:?} | tempo {:.2}s | {:.2} MiB/s",
                parts.len(),
                outdir,
                dt,
                mbps
            );
        }
        Commands::ContainerReveal {
            stego,
            outdir,
            password,
        } => {
            let out = outdir.unwrap_or_else(|| stego.with_extension("out"));
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("CONT", &p));
            let restored = unwrap_container_png_to_dir(&stego, &out, password.as_deref(), Some(cb))?;
            let total = std::fs::metadata(&restored).map(|m| m.len() as f64).unwrap_or(0.0);
            let dt = t0.elapsed().as_secs_f64();
            let mbps = if dt > 0.0 {
                total / (1024.0 * 1024.0) / dt
            } else {
                0.0
            };
            println!(
                "[OK] 1 ficheiro extraído: {:?} | tempo {:.2}s | {:.2} MiB/s",
                restored, dt, mbps
            );
        }
        Commands::ContainerSplit {
            stego,
            cover,
            outdir,
            max_bytes,
            max_gib,
            password,
        } => {
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("CONT", &p));
            let max_bytes = max_gib
                .map(|g| g.saturating_mul(1024 * 1024 * 1024))
                .unwrap_or(max_bytes);
            let parts = split_container_png_to_parts(
                &stego,
                Some(&cover),
                &outdir,
                max_bytes,
                password.as_deref(),
                Some(cb),
            )?;
            let dt = t0.elapsed().as_secs_f64();
            println!(
                "[OK] {} partes em {:?} | tempo {:.2}s",
                parts.len(),
                outdir,
                dt
            );
        }
        Commands::ContainerJoin {
            outfile,
            mut parts,
            indir,
            password,
        } => {
            if parts.is_empty() {
                let dir = indir.ok_or_else(|| anyhow::anyhow!("Indica partes ou --indir"))?;
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("png"))
                        .unwrap_or(false)
                    {
                        parts.push(path);
                    }
                }
            }
            if parts.is_empty() {
                anyhow::bail!("Sem partes PNG para juntar.");
            }
            let t0 = Instant::now();
            let cb = Arc::new(|p: ProgressUpdate| print_progress("CONT", &p));
            join_container_png_parts_to_file(&parts, &outfile, password.as_deref(), Some(cb))?;
            let dt = t0.elapsed().as_secs_f64();
            println!("[OK] ficheiro em {:?} | tempo {:.2}s", outfile, dt);
        }
        Commands::SwapCover {
            stego,
            new_cover,
            outfile,
            password,
            bpc,
            allow_upscale,
        } => {
            let opts = EncryptOptions {
                password,
                bpc,
                allow_upscale,
            };
            let t0 = Instant::now();
            swap_cover(&stego, &new_cover, &outfile, opts.password.clone(), &opts)?;
            let dt = t0.elapsed().as_secs_f64();
            println!(
                "[OK] payload re-embedado em {:?} | tempo {:.2}s",
                outfile, dt
            );
        }
        Commands::Info { image, bpc } => {
            let (w, h, cap) = info_capacity(&image, bpc)?;
            println!(
                "[INFO] {}x{} | bpc={} | cap ~{:.2} MiB",
                w,
                h,
                bpc,
                cap as f64 / (1024.0 * 1024.0)
            );
        }
        Commands::Topic { topic } => help::print_topic(topic.as_deref()),
        Commands::Bench { size, bpc, out } => {
            println!(
                "[BENCH] A criar recursos e medir embed de {} ...",
                fmt_size(size)
            );
            let (dt, mib_s) = run_benchmark(size, bpc)?;
            println!("[BENCH] Tempo {:.2}s → {:.2} MiB/s", dt, mib_s);

            let outfile = out.unwrap_or_else(|| PathBuf::from("output/bench_estimates.txt"));
            let sizes = size_list();
            if let Some(parent) = outfile.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut buf = String::new();
            buf.push_str("# Estimativa de tempos para f2png-cli (Rust)\n");
            buf.push_str(&format!(
                "# Benchmark real: esconder {} a ~{:.2} MiB/s\n",
                fmt_size(size),
                mib_s
            ));
            buf.push_str(
                "# Formato: tamanho_bytes\tTamanho_humano\tSegundos_est\tTempo_humano\n\n",
            );
            for sz in sizes {
                let seconds = (sz as f64) / (mib_s * 1024.0 * 1024.0);
                buf.push_str(&format!(
                    "{}\t{}\t{:.3}\t{}\n",
                    sz,
                    fmt_size(sz),
                    seconds,
                    fmt_time(seconds)
                ));
            }
            std::fs::write(&outfile, buf)?;
            println!("[BENCH] Tabela escrita em {:?}", outfile);
        }
        Commands::BenchContainerEmbed { size, password, out } => {
            println!(
                "[BENCH] Container embed de {} ...",
                fmt_size(size)
            );
            let (dt, mib_s) = run_container_embed_benchmark(size, password.as_deref())?;
            println!("[BENCH] Tempo {:.2}s → {:.2} MiB/s", dt, mib_s);

            let outfile = out.unwrap_or_else(|| PathBuf::from("output/bench_container_embed.txt"));
            let sizes = size_list();
            if let Some(parent) = outfile.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut buf = String::new();
            buf.push_str("# Estimativa container embed (Rust)\n");
            buf.push_str(&format!(
                "# Benchmark real: esconder {} a ~{:.2} MiB/s\n",
                fmt_size(size),
                mib_s
            ));
            buf.push_str(
                "# Formato: tamanho_bytes\tTamanho_humano\tSegundos_est\tTempo_humano\n\n",
            );
            for sz in sizes {
                let seconds = (sz as f64) / (mib_s * 1024.0 * 1024.0);
                buf.push_str(&format!(
                    "{}\t{}\t{:.3}\t{}\n",
                    sz,
                    fmt_size(sz),
                    seconds,
                    fmt_time(seconds)
                ));
            }
            std::fs::write(&outfile, buf)?;
            println!("[BENCH] Tabela escrita em {:?}", outfile);
        }
        Commands::BenchContainerReveal { size, password, out } => {
            println!(
                "[BENCH] Container reveal de {} ...",
                fmt_size(size)
            );
            let (dt, mib_s) = run_container_reveal_benchmark(size, password.as_deref())?;
            println!("[BENCH] Tempo {:.2}s → {:.2} MiB/s", dt, mib_s);

            let outfile = out.unwrap_or_else(|| PathBuf::from("output/bench_container_reveal.txt"));
            let sizes = size_list();
            if let Some(parent) = outfile.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut buf = String::new();
            buf.push_str("# Estimativa container reveal (Rust)\n");
            buf.push_str(&format!(
                "# Benchmark real: revelar {} a ~{:.2} MiB/s\n",
                fmt_size(size),
                mib_s
            ));
            buf.push_str(
                "# Formato: tamanho_bytes\tTamanho_humano\tSegundos_est\tTempo_humano\n\n",
            );
            for sz in sizes {
                let seconds = (sz as f64) / (mib_s * 1024.0 * 1024.0);
                buf.push_str(&format!(
                    "{}\t{}\t{:.3}\t{}\n",
                    sz,
                    fmt_size(sz),
                    seconds,
                    fmt_time(seconds)
                ));
            }
            std::fs::write(&outfile, buf)?;
            println!("[BENCH] Tabela escrita em {:?}", outfile);
        }
    }
    Ok(())
}
