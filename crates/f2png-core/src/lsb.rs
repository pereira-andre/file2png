use anyhow::Result;
use image::{imageops::FilterType, DynamicImage, GenericImageView, ImageBuffer, Rgba};
use rayon::prelude::*;
use std::sync::atomic::AtomicBool;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const CHANNELS_USED: usize = 3;
const RGBA_STRIDE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressPhase {
    Prepare,
    Encrypt,
    Embed,
    Save,
    Extract,
    Decrypt,
    Parse,
}

#[derive(Clone, Debug)]
pub struct ProgressUpdate {
    pub phase: ProgressPhase,
    pub percent: f32,
    pub elapsed: f64,
    pub eta: Option<f64>,
    pub speed_mib_s: f64,
}

pub type ProgressCb = Option<Arc<dyn Fn(ProgressUpdate) + Send + Sync>>;

#[derive(Clone)]
pub struct BlobRef<'a> {
    head: &'a [u8],
    tail: &'a [u8],
}

impl<'a> BlobRef<'a> {
    pub fn new(head: &'a [u8], tail: &'a [u8]) -> Self {
        Self { head, tail }
    }

    #[inline]
    pub fn len_bytes(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    #[inline]
    pub fn byte_at(&self, idx: usize) -> u8 {
        if idx < self.head.len() {
            self.head[idx]
        } else {
            self.tail[idx - self.head.len()]
        }
    }
}

pub fn capacity_bytes(img: &DynamicImage, bpc: u8) -> usize {
    let (w, h) = img.dimensions();
    let pixels = (w as usize) * (h as usize);
    pixels * CHANNELS_USED * (bpc as usize) / 8
}

fn ensure_capacity(
    img: DynamicImage,
    bpc: u8,
    payload_len: usize,
    allow_upscale: bool,
) -> Result<DynamicImage> {
    let cap = capacity_bytes(&img, bpc);
    if payload_len <= cap {
        return Ok(img);
    }
    if !allow_upscale {
        anyhow::bail!("Payload maior que a capacidade e upscale desativado.");
    }
    let bits_per_pixel = (CHANNELS_USED as u64) * (bpc as u64);
    let required_bits = (payload_len as u64) * 8;
    let (w, h) = img.dimensions();
    let current_bits = (w as u64) * (h as u64) * bits_per_pixel;
    let scale = ((required_bits as f64 / current_bits as f64).sqrt() * 1.01).max(1.0);
    let new_w = ((w as f64) * scale).ceil() as u32;
    let new_h = ((h as f64) * scale).ceil() as u32;

    // Guardrails: evitar allocations absurdas (OOM) ao fazer upscale automático.
    // Override opcional via env `F2PNG_MAX_PIXELS`.
    let max_pixels_default: u64 = 512_000_000; // ~2 GiB RGBA (4 bytes/pixel)
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
            "Upscale exigiria imagem enorme ({}x{} = {} px, ~{:.2} GiB RGBA). \
Use uma capa maior, aumente --bpc, ou define F2PNG_MAX_PIXELS para permitir.",
            new_w,
            new_h,
            pixels,
            gib
        );
    }

    // Triangle (bilinear) é bastante mais rápido que Lanczos3 e suficiente para uma “capa”.
    Ok(img.resize_exact(new_w, new_h, FilterType::Triangle))
}

pub fn embed_lsb_parallel(
    img: DynamicImage,
    data: BlobRef<'_>,
    bpc: u8,
    allow_upscale: bool,
    progress: ProgressCb,
) -> Result<DynamicImage> {
    if bpc == 0 || bpc > 4 {
        anyhow::bail!("BPC inválido (use 1..=4).");
    }
    let img = ensure_capacity(img, bpc, data.len_bytes(), allow_upscale)?;
    let mut rgba: ImageBuffer<Rgba<u8>, Vec<u8>> = img.to_rgba8();
    let mask: u8 = (1u8 << bpc) - 1;
    let total_bits = data.len_bytes() * 8;
    let bits_per_pixel = (bpc as usize) * CHANNELS_USED;
    let pixels_needed = (total_bits + bits_per_pixel - 1) / bits_per_pixel;
    let total_pixels = rgba.len() / RGBA_STRIDE;
    let pixels_to_touch = pixels_needed.min(total_pixels);

    let start = Instant::now();
    let processed = Arc::new(AtomicUsize::new(0));
    let done_flag = Arc::new(AtomicBool::new(false));
    let reporter = progress.as_ref().map(|cb| {
        let cb = Arc::clone(cb);
        let processed = Arc::clone(&processed);
        let done_flag = Arc::clone(&done_flag);
        let total_bits_f = total_bits as f64;
        thread::spawn(move || loop {
            let done = processed.load(Ordering::Relaxed);
            let percent = (done as f64 / total_bits_f * 100.0).min(100.0) as f32;
            let elapsed = start.elapsed().as_secs_f64();
            let speed_mib_s = if elapsed > 0.0 {
                (done as f64 / 8.0) / (1024.0 * 1024.0) / elapsed
            } else {
                0.0
            };
            let remaining_bits = (total_bits_f as usize).saturating_sub(done);
            let eta = if speed_mib_s > 0.0 {
                Some((remaining_bits as f64 / 8.0) / (1024.0 * 1024.0) / speed_mib_s)
            } else {
                None
            };
            cb(ProgressUpdate {
                phase: ProgressPhase::Embed,
                percent,
                elapsed,
                eta,
                speed_mib_s,
            });
            if done_flag.load(Ordering::Relaxed) || done >= total_bits_f as usize {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        })
    });

    rgba.par_chunks_mut(RGBA_STRIDE)
        .take(pixels_to_touch)
        .enumerate()
        .for_each_init(
            || 0usize,
            |local_acc, (idx, px)| {
                let start_bit = idx * bits_per_pixel;
                if start_bit >= total_bits {
                    return;
                }
                let mut local_bits = 0usize;
                for chan in 0..CHANNELS_USED {
                    if start_bit + local_bits >= total_bits {
                        break;
                    }
                    let mut new_bits: u8 = 0;
                    for b in 0..bpc {
                        let global_bit = start_bit + local_bits;
                        if global_bit >= total_bits {
                            break;
                        }
                        let byte_i = global_bit / 8;
                        let bit_i = (global_bit % 8) as u8;
                        let byte = data.byte_at(byte_i);
                        let bit_val = (byte >> bit_i) & 1;
                        new_bits |= bit_val << b;
                        local_bits += 1;
                    }
                    px[chan] = (px[chan] & !mask) | new_bits;
                }

                *local_acc += local_bits;
                if *local_acc >= 1 << 20 {
                    processed.fetch_add(*local_acc, Ordering::Relaxed);
                    *local_acc = 0;
                }
            },
        );

    processed.store(total_bits, Ordering::Relaxed);
    done_flag.store(true, Ordering::Relaxed);
    if let Some(handle) = reporter {
        let _ = handle.join();
    }

    Ok(DynamicImage::ImageRgba8(rgba))
}

pub fn extract_lsb(img: &DynamicImage, bpc: u8) -> Result<Vec<u8>> {
    extract_lsb_with_progress(img, bpc, None)
}

pub fn extract_lsb_with_progress(
    img: &DynamicImage,
    bpc: u8,
    progress: ProgressCb,
) -> Result<Vec<u8>> {
    if bpc == 0 || bpc > 4 {
        anyhow::bail!("BPC inválido (use 1..=4).");
    }
    let data = img.to_rgba8();
    let mut out = Vec::with_capacity(data.len());
    let mask: u8 = (1u8 << bpc) - 1;
    let mut current: u8 = 0;
    let mut bits_filled: u8 = 0;
    let total_bits = data.len() * bpc as usize / RGBA_STRIDE * CHANNELS_USED; // aprox: per pixel 3*bpc bits
    let start = Instant::now();
    let mut last_report = 0usize;
    let report_every = (total_bits / 100).max(1);
    for px in data.pixels() {
        for chan in 0..CHANNELS_USED {
            let chunk = px[chan] & mask;
            for b in 0..bpc {
                let bit_val = (chunk >> b) & 1;
                current |= bit_val << bits_filled;
                bits_filled += 1;
                if bits_filled == 8 {
                    out.push(current);
                    current = 0;
                    bits_filled = 0;
                }
                let done = out.len() * 8;
                if let Some(cb) = progress.as_deref() {
                    if done >= last_report + report_every || done >= total_bits {
                        last_report = done;
                        let elapsed = start.elapsed().as_secs_f64();
                        let percent = (done as f32 / total_bits as f32 * 100.0).min(100.0);
                        let speed_mib_s = if elapsed > 0.0 {
                            (done as f64 / 8.0) / (1024.0 * 1024.0) / elapsed
                        } else {
                            0.0
                        };
                        let remaining_bits = total_bits.saturating_sub(done);
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
            }
        }
    }
    Ok(out)
}

pub struct BitStreamReader {
    data: image::RgbaImage,
    bpc: u8,
    mask: u8,
    byte_acc: u8,
    bits_filled: u8,
    pixel_idx: usize,
    channel_idx: usize,
    bit_in_channel: u8,
}

impl BitStreamReader {
    pub fn new(img: &DynamicImage, bpc: u8) -> Result<Self> {
        if bpc == 0 || bpc > 4 {
            anyhow::bail!("BPC inválido (use 1..=4).");
        }
        Ok(Self {
            data: img.to_rgba8(),
            bpc,
            mask: (1u8 << bpc) - 1,
            byte_acc: 0,
            bits_filled: 0,
            pixel_idx: 0,
            channel_idx: 0,
            bit_in_channel: 0,
        })
    }

    #[inline]
    pub fn bits_read(&self) -> usize {
        self.pixel_idx * CHANNELS_USED * self.bpc as usize
            + self.channel_idx * self.bpc as usize
            + self.bit_in_channel as usize
    }

    #[inline]
    pub fn capacity_bits(&self) -> usize {
        self.data.len() * self.bpc as usize / RGBA_STRIDE * CHANNELS_USED
    }

    pub fn next_byte(&mut self) -> Option<u8> {
        let total_bits = self.capacity_bits();
        while self.bits_filled < 8 {
            if self.bits_read() >= total_bits {
                return None;
            }
            let px = &self.data.as_raw()
                [(self.pixel_idx * RGBA_STRIDE)..(self.pixel_idx * RGBA_STRIDE + RGBA_STRIDE)];
            let chunk = px[self.channel_idx] & self.mask;
            let bit_val = (chunk >> self.bit_in_channel) & 1;
            self.byte_acc |= bit_val << self.bits_filled;
            self.bits_filled += 1;
            self.bit_in_channel += 1;
            if self.bit_in_channel as u8 >= self.bpc {
                self.bit_in_channel = 0;
                self.channel_idx += 1;
                if self.channel_idx >= CHANNELS_USED {
                    self.channel_idx = 0;
                    self.pixel_idx += 1;
                }
            }
        }
        let out = self.byte_acc;
        self.byte_acc = 0;
        self.bits_filled = 0;
        Some(out)
    }
}
