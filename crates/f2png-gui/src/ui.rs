use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use f2png_core::lsb::{ProgressPhase, ProgressUpdate};
use f2png_core::{
    embed_multi, embed_single_file, is_container_png, join_container_png_parts_to_file,
    reveal_to_dir, split_container_png_to_parts, unwrap_container_png_to_dir,
    wrap_single_file_container_png, wrap_single_file_container_png_parts, EncryptOptions,
};

const STREAM_CHUNK: u64 = 4 * 1024 * 1024;
const TAG_SIZE: u64 = 16;

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

fn section_frame(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(28, 30, 38))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::same(12.0))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 58)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(title);
            });
            ui.add_space(6.0);
            add_contents(ui);
        });
}

pub struct F2PngApp {
    tab: Tab,
    cover: Option<PathBuf>,
    files: Vec<PathBuf>,
    out: Option<PathBuf>,
    out_reveal: Option<PathBuf>,
    bpc: u8,
    password: String,
    allow_upscale: bool,
    container_mode: bool,
    container_split: bool,
    container_limit_preset: bool,
    container_limit_gib: u64,
    container_max_mib: u64,
    container_outdir: Option<PathBuf>,
    split_container: bool,
    split_cover: Option<PathBuf>,
    split_limit_preset: bool,
    split_limit_gib: u64,
    split_max_mib: u64,
    split_outdir: Option<PathBuf>,
    join_parts: Vec<PathBuf>,
    join_out: Option<PathBuf>,
    log: String,
    progress_label: String,
    progress_value: f32,
    progress_speed: f64,
    progress_eta: Option<f64>,
    busy: bool,
    rx: Option<Receiver<UiMessage>>,
}

#[derive(PartialEq)]
enum Tab {
    Embed,
    Reveal,
    Tests,
    Help,
}

enum UiMessage {
    Progress {
        label: String,
        update: ProgressUpdate,
    },
    Info {
        msg: String,
    },
    Done {
        log: String,
    },
    Error {
        err: String,
    },
}

impl F2PngApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.window_margin = egui::Margin::same(12.0);
        style.visuals.window_rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
        style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(20.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(15.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            egui::FontId::new(12.0, egui::FontFamily::Proportional),
        );
        cc.egui_ctx.set_style(style);
        Self {
            tab: Tab::Embed,
            cover: None,
            files: Vec::new(),
            out: None,
            out_reveal: None,
            bpc: 2,
            password: String::new(),
            allow_upscale: true,
            container_mode: false,
            container_split: false,
            container_limit_preset: true,
            container_limit_gib: 2,
            container_max_mib: 2048,
            container_outdir: None,
            split_container: false,
            split_cover: None,
            split_limit_preset: true,
            split_limit_gib: 2,
            split_max_mib: 2048,
            split_outdir: None,
            join_parts: Vec::new(),
            join_out: None,
            log: String::new(),
            progress_label: "Pronto".into(),
            progress_value: 0.0,
            progress_speed: 0.0,
            progress_eta: None,
            busy: false,
            rx: None,
        }
    }

    fn push_log(&mut self, msg: &str) {
        self.log.push_str(msg);
        self.log.push('\n');
        if self.log.len() > 10_000 {
            let keep = self.log.chars().rev().take(5000).collect::<String>();
            self.log = keep.chars().rev().collect();
        }
    }

    fn apply_progress(&mut self, label: &str, p: ProgressUpdate) {
        self.progress_label = label.to_string();
        self.progress_value = p.percent;
        self.progress_speed = p.speed_mib_s;
        self.progress_eta = p.eta;
    }
}

fn start_prepare_ticker(tx: mpsc::Sender<UiMessage>, label: &str) -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);
    let label = label.to_string();
    thread::spawn(move || {
        let start = Instant::now();
        while flag.load(Ordering::Relaxed) {
            let elapsed = start.elapsed().as_secs_f64();
            let _ = tx.send(UiMessage::Progress {
                label: label.clone(),
                update: ProgressUpdate {
                    phase: ProgressPhase::Prepare,
                    percent: 0.0,
                    elapsed,
                    eta: None,
                    speed_mib_s: 0.0,
                },
            });
            thread::sleep(Duration::from_millis(700));
        }
    });
    running
}

impl eframe::App for F2PngApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        if let Some(rx_owned) = self.rx.take() {
            while let Ok(msg) = rx_owned.try_recv() {
                match msg {
                    UiMessage::Progress { label, update } => self.apply_progress(&label, update),
                    UiMessage::Info { msg } => self.push_log(&msg),
                    UiMessage::Done { log } => {
                        self.busy = false;
                        self.progress_value = 100.0;
                        self.progress_label = "Pronto".into();
                        self.progress_eta = None;
                        self.push_log(&log);
                    }
                    UiMessage::Error { err } => {
                        self.busy = false;
                        self.progress_label = "Erro".into();
                        self.progress_value = 0.0;
                        self.progress_speed = 0.0;
                        self.progress_eta = None;
                        self.push_log(&format!("ERRO: {err}"));
                    }
                }
            }
            self.rx = Some(rx_owned);
        }

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(24, 26, 32))
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("f2png").strong().size(18.0));
                    ui.separator();
                    ui.selectable_value(&mut self.tab, Tab::Embed, "Esconder");
                    ui.selectable_value(&mut self.tab, Tab::Reveal, "Revelar");
                    ui.selectable_value(&mut self.tab, Tab::Tests, "Testes");
                    ui.selectable_value(&mut self.tab, Tab::Help, "Ajuda");
                });
            });

        egui::TopBottomPanel::top("progress_panel")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(32, 35, 45))
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Estado:");
                    ui.strong(if self.busy { &self.progress_label } else { "Pronto" });
                });
                ui.add(
                    egui::ProgressBar::new((self.progress_value / 100.0).clamp(0.0, 1.0))
                        .show_percentage()
                        .animate(true),
                );
                ui.horizontal(|ui| {
                    ui.label(format!("Velocidade: {:.2} MiB/s", self.progress_speed));
                    ui.label(format!(
                        "ETA: {}",
                        self.progress_eta
                            .map(format_eta)
                            .unwrap_or_else(|| "--".into())
                    ));
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Embed => self.ui_embed(ui),
            Tab::Reveal => self.ui_reveal(ui),
            Tab::Tests => self.ui_tests(ui),
            Tab::Help => self.ui_help(ui),
        });

        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(220.0)
            .min_height(140.0)
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(24, 26, 32))
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Log");
                    ui.separator();
                    if ui.button("Copiar").clicked() {
                        ui.output_mut(|o| o.copied_text = self.log.clone());
                    }
                    if ui.button("Limpar").clicked() {
                        self.log.clear();
                    }
                });
                let log_height = ui.available_height().max(120.0);
                ui.add_sized(
                    [ui.available_width(), log_height],
                    egui::TextEdit::multiline(&mut self.log)
                        .desired_rows(12)
                        .code_editor()
                        .lock_focus(true)
                        .desired_width(f32::INFINITY),
                );
            });
    }
}

impl F2PngApp {
    fn ui_embed(&mut self, ui: &mut egui::Ui) {
        section_frame(ui, "Esconder ficheiro(s)", |ui| {
            ui.columns(2, |cols| {
                let (left, right) = cols.split_at_mut(1);
                let left = &mut left[0];
                let right = &mut right[0];

                left.vertical(|ui| {
                    file_picker(ui, "Imagem de cobertura", &mut self.cover, !self.container_mode);
                    self.ui_capacity_hint(ui);
                    ui.horizontal(|ui| {
                        if ui.button("Adicionar ficheiro...").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                if !self.files.contains(&path) {
                                    self.files.push(path);
                                }
                            }
                        }
                        if ui.button("Adicionar vários...").clicked() {
                            if let Some(paths) = rfd::FileDialog::new().pick_files() {
                                for p in paths {
                                    if !self.files.contains(&p) {
                                        self.files.push(p);
                                    }
                                }
                            }
                        }
                        if ui.button("Limpar lista").clicked() {
                            self.files.clear();
                        }
                    });
                    egui::ScrollArea::vertical()
                        .max_height(140.0)
                        .show(ui, |ui| {
                            if self.files.is_empty() {
                                ui.label("(sem ficheiros adicionados)");
                            } else {
                                for p in &self.files {
                                    ui.label(p.display().to_string());
                                }
                            }
                        });
                    if self.container_mode && self.container_split {
                        ui.horizontal(|ui| {
                            ui.label("Destino (pasta):");
                            let mut out_txt = self
                                .container_outdir
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default();
                            let response = ui.text_edit_singleline(&mut out_txt);
                            if response.lost_focus() && !out_txt.is_empty() {
                                self.container_outdir = Some(PathBuf::from(out_txt.trim()));
                            }
                            if ui.button("Escolher dir...").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                    self.container_outdir = Some(path);
                                }
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            ui.label("Saída (PNG):");
                            let mut out_txt = self
                                .out
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default();
                            let response = ui.text_edit_singleline(&mut out_txt);
                            if response.lost_focus() && !out_txt.is_empty() {
                                self.out = Some(PathBuf::from(out_txt.trim()));
                            }
                            if ui.button("Escolher...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("PNG", &["png"])
                                    .save_file()
                                {
                                    self.out = Some(path);
                                }
                            }
                        });
                    }
                });

                right.vertical(|ui| {
                    ui.checkbox(
                        &mut self.container_mode,
                        "Modo container (suporta ficheiros grandes, não usa LSB)",
                    );
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("Dica: use container para ficheiros grandes.")
                                .small()
                                .color(egui::Color32::from_gray(170)),
                        )
                        .wrap(true),
                    );
                    ui.horizontal(|ui| {
                        ui.label("Password (opcional):");
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    });
                    ui.collapsing("Opcoes avancadas", |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Bits por canal:");
                            ui.add(egui::Slider::new(&mut self.bpc, 1..=4));
                        });
                        ui.checkbox(&mut self.allow_upscale, "Permitir upscale automatico");
                    });

                    if self.container_mode {
                        ui.collapsing("Container: dividir em partes", |ui| {
                            ui.checkbox(&mut self.container_split, "Dividir em partes (< limite)");
                            if self.container_split {
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut self.container_limit_preset, "Usar preset (GiB)");
                                    if self.container_limit_preset {
                                        egui::ComboBox::from_id_source("container_limit_gib")
                                            .selected_text(format!("{} GiB", self.container_limit_gib))
                                            .show_ui(ui, |ui| {
                                                for v in [2u64, 4, 8, 16, 32, 64, 128] {
                                                    ui.selectable_value(
                                                        &mut self.container_limit_gib,
                                                        v,
                                                        format!("{} GiB", v),
                                                    );
                                                }
                                            });
                                    } else {
                                        ui.label("Max por PNG (MiB):");
                                        ui.add(
                                            egui::DragValue::new(&mut self.container_max_mib)
                                                .clamp_range(1..=131072),
                                        );
                                    }
                                });
                            }
                        });
                    }
                });
            });

            ui.add_space(6.0);
            if ui
                .add_enabled(!self.busy, egui::Button::new("Esconder → PNG"))
                .clicked()
            {
                if self.files.is_empty() {
                    self.push_log("ERRO: adiciona pelo menos um ficheiro.");
                    return;
                }
                if self.container_mode && self.files.len() != 1 {
                    self.push_log("ERRO: modo container só suporta 1 ficheiro (por agora).");
                    return;
                }
                if !self.container_mode && self.cover.is_none() {
                    self.push_log("ERRO: escolhe imagem de cobertura.");
                    return;
                }

                let container_split = self.container_split;
                let container_limit_preset = self.container_limit_preset;
                let container_limit_gib = self.container_limit_gib;
                let container_max_mib = self.container_max_mib;
                let out_dir_split = self.container_outdir.clone();
                let out = if self.container_mode && self.container_split {
                    out_dir_split.unwrap_or_else(|| {
                        self.files
                            .get(0)
                            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                            .unwrap_or_else(|| PathBuf::from("."))
                    })
                } else {
                    self.out.clone().unwrap_or_else(|| {
                        let first = self.files.get(0).cloned().unwrap();
                        first.with_extension("stego.png")
                    })
                };
                    let opts = EncryptOptions {
                        password: if self.password.is_empty() {
                            None
                        } else {
                            Some(self.password.clone())
                        },
                        bpc: self.bpc,
                        allow_upscale: self.allow_upscale,
                    };
                    let cover = self.cover.clone();
                    let files = self.files.clone();
                    let out_clone = out.clone();
                    let container_mode = self.container_mode;
                    let container_split = container_split;
                    let container_limit_preset = container_limit_preset;
                    let container_limit_gib = container_limit_gib;
                    let container_max_mib = container_max_mib;
                    self.push_log(&format!(
                        "A iniciar embed: cover='{}', out='{}', ficheiros={}, bpc={}, password_set={}, allow_upscale={}, container_mode={}, split={}",
                        cover
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "(auto)".into()),
                        out_clone.display(),
                        files.len(),
                        opts.bpc,
                        opts.password.is_some(),
                        opts.allow_upscale,
                        container_mode,
                        container_split
                    ));
                    self.busy = true;
                    self.progress_value = 0.0;
                    let (tx, rx) = mpsc::channel();
                    self.rx = Some(rx);
                    thread::spawn(move || {
                        let ticker_flag = start_prepare_ticker(tx.clone(), "A preparar (hash/cifra)");
                        let total: f64 = files
                            .iter()
                            .map(|p| std::fs::metadata(p).map(|m| m.len() as f64).unwrap_or(0.0))
                            .sum();
                        let t0 = Instant::now();
                        let tx_progress = tx.clone();
                        let cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(move |p: ProgressUpdate| {
                            let _ = tx_progress.send(UiMessage::Progress {
                                label: "A esconder".into(),
                                update: p,
                            });
                        });
                        let _ = tx.send(UiMessage::Info {
                            msg: format!(
                                "Embed em curso → cover='{}', out='{}', ficheiros={}, bpc={}, container_mode={}, split={}",
                                cover
                                    .as_ref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "(auto)".into()),
                                out_clone.display(),
                                files.len(),
                                opts.bpc,
                                container_mode,
                                container_split
                            ),
                        });
                        let res = if container_mode && container_split {
                            let max_bytes = if container_limit_preset {
                                container_limit_gib.saturating_mul(1024 * 1024 * 1024)
                            } else {
                                container_max_mib.saturating_mul(1024 * 1024)
                            };
                            wrap_single_file_container_png_parts(
                                cover.as_deref(),
                                &files[0],
                                &out_clone,
                                max_bytes,
                                opts.password.as_deref(),
                                Some(Arc::clone(&cb)),
                            )
                            .map(|_| ())
                        } else if container_mode {
                            wrap_single_file_container_png(
                                cover.as_deref(),
                                &files[0],
                                &out_clone,
                                opts.password.as_deref(),
                                Some(Arc::clone(&cb)),
                            )
                        } else if files.len() == 1 {
                            let cover = cover.expect("cover required");
                            embed_single_file(
                                &cover,
                                &files[0],
                                &out_clone,
                                &opts,
                                Some(Arc::clone(&cb)),
                            )
                            .map(|_| ())
                        } else {
                            let cover = cover.expect("cover required");
                            embed_multi(&cover, &files, &out_clone, &opts, Some(Arc::clone(&cb)))
                                .map(|_| ())
                        };
                        ticker_flag.store(false, Ordering::Relaxed);
                        match res {
                            Ok(()) => {
                                let dt = t0.elapsed().as_secs_f64();
                                let mbps = if dt > 0.0 {
                                    total / (1024.0 * 1024.0) / dt
                                } else {
                                    0.0
                                };
                                let log = format!(
                                    "OK: {} | {:.2}s | {:.2} MiB/s",
                                    out_clone.display(),
                                    dt,
                                    mbps
                                );
                                let _ = tx.send(UiMessage::Done { log });
                            }
                            Err(e) => {
                                let _ = tx.send(UiMessage::Error { err: e.to_string() });
                            }
                        }
                    });
            }
        });
    }

    fn ui_reveal(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            let (left, right) = cols.split_at_mut(1);
            let left = &mut left[0];
            let right = &mut right[0];

            left.vertical(|ui| {
                section_frame(ui, "Revelar ficheiro(s)", |ui| {
                    file_picker(ui, "Imagem stego", &mut self.cover, true);
                    ui.horizontal(|ui| {
                        ui.label("Destino:");
                        let mut out_txt = self
                            .out_reveal
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        let response = ui.text_edit_singleline(&mut out_txt);
                        if response.lost_focus() && !out_txt.is_empty() {
                            self.out_reveal = Some(PathBuf::from(out_txt.trim()));
                        }
                        if ui.button("Escolher dir...").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.out_reveal = Some(path);
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Password (se cifrado):");
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    });
                    ui.collapsing("Opcoes avancadas", |ui| {
                        ui.checkbox(&mut self.split_container, "Separar container em partes");
                        if self.split_container {
                            file_picker(ui, "Imagem de cobertura", &mut self.split_cover, true);
                            ui.horizontal(|ui| {
                                ui.label("Destino (pasta):");
                                let mut out_txt = self
                                    .split_outdir
                                    .as_ref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default();
                                let response = ui.text_edit_singleline(&mut out_txt);
                                if response.lost_focus() && !out_txt.is_empty() {
                                    self.split_outdir = Some(PathBuf::from(out_txt.trim()));
                                }
                                if ui.button("Escolher dir...").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.split_outdir = Some(path);
                                    }
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.split_limit_preset, "Usar preset (GiB)");
                                if self.split_limit_preset {
                                    egui::ComboBox::from_id_source("split_limit_gib")
                                        .selected_text(format!("{} GiB", self.split_limit_gib))
                                        .show_ui(ui, |ui| {
                                            for v in [2u64, 4, 8, 16, 32, 64, 128] {
                                                ui.selectable_value(
                                                    &mut self.split_limit_gib,
                                                    v,
                                                    format!("{} GiB", v),
                                                );
                                            }
                                        });
                                } else {
                                    ui.label("Max por PNG (MiB):");
                                    ui.add(
                                        egui::DragValue::new(&mut self.split_max_mib)
                                            .clamp_range(1..=131072),
                                    );
                                }
                            });
                        }
                    });
                    if ui.add_enabled(!self.busy, egui::Button::new("Revelar")).clicked() {
                        if let Some(stego) = &self.cover {
                            let outdir = self
                                .out_reveal
                                .clone()
                                .unwrap_or_else(|| stego.with_extension("out"));
                            let pw =
                                if self.password.is_empty() { None } else { Some(self.password.clone()) };
                            let stego_clone = stego.clone();
                            self.push_log(&format!(
                                "A iniciar reveal: stego='{}', outdir='{}', bpc=2, password_set={}, split={}",
                                stego.display(),
                                outdir.display(),
                                pw.is_some(),
                                self.split_container
                            ));
                            self.busy = true;
                            self.progress_value = 0.0;
                            let (tx, rx) = mpsc::channel();
                            self.rx = Some(rx);
                            let split_container = self.split_container;
                            let split_cover = self.split_cover.clone();
                            let split_outdir = self.split_outdir.clone();
                            let split_limit_preset = self.split_limit_preset;
                            let split_limit_gib = self.split_limit_gib;
                            let split_max_mib = self.split_max_mib;
                            thread::spawn(move || {
                                let ticker_flag = start_prepare_ticker(tx.clone(), "A preparar (ler/decifrar)");
                                let t0 = Instant::now();
                                let tx_progress = tx.clone();
                                let cb = Arc::new(move |p: ProgressUpdate| {
                                    let _ = tx_progress.send(UiMessage::Progress {
                                        label: "A revelar".into(),
                                        update: p,
                                    });
                                });
                                let is_container = is_container_png(&stego_clone);
                                let _ = tx.send(UiMessage::Info {
                                    msg: format!(
                                        "Reveal em curso → stego='{}', outdir='{}', mode={}, split={}",
                                        stego_clone.display(),
                                        outdir.display(),
                                        if is_container { "container" } else { "lsb" },
                                        split_container
                                    ),
                                });
                                ticker_flag.store(false, Ordering::Relaxed);
                                if split_container {
                                    let cover = match split_cover.as_ref() {
                                        Some(c) => c,
                                        None => {
                                            let _ = tx.send(UiMessage::Error {
                                                err: "Capa obrigatória para separar em partes.".into(),
                                            });
                                            return;
                                        }
                                    };
                                    let outdir =
                                        split_outdir.unwrap_or_else(|| stego_clone.with_extension("parts"));
                                    let max_bytes = if split_limit_preset {
                                        split_limit_gib.saturating_mul(1024 * 1024 * 1024)
                                    } else {
                                        split_max_mib.saturating_mul(1024 * 1024)
                                    };
                                    let res = split_container_png_to_parts(
                                        &stego_clone,
                                        Some(cover),
                                        &outdir,
                                        max_bytes,
                                        pw.as_deref(),
                                        Some(cb),
                                    );
                                    match res {
                                        Ok(parts) => {
                                            let dt = t0.elapsed().as_secs_f64();
                                            let log = format!(
                                                "OK: {} partes → {} | {:.2}s",
                                                parts.len(),
                                                outdir.display(),
                                                dt
                                            );
                                            let _ = tx.send(UiMessage::Done { log });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(UiMessage::Error { err: e.to_string() });
                                        }
                                    }
                                } else if is_container {
                                    let res = unwrap_container_png_to_dir(
                                        &stego_clone,
                                        &outdir,
                                        pw.as_deref(),
                                        Some(cb),
                                    );
                                    match res {
                                        Ok(path) => {
                                            let total =
                                                std::fs::metadata(&path).map(|m| m.len() as f64).unwrap_or(0.0);
                                            let dt = t0.elapsed().as_secs_f64();
                                            let mbps = if dt > 0.0 {
                                                total / (1024.0 * 1024.0) / dt
                                            } else {
                                                0.0
                                            };
                                            let log = format!(
                                                "OK: 1 ficheiro → {} | {:.2}s | {:.2} MiB/s",
                                                path.display(),
                                                dt,
                                                mbps
                                            );
                                            let _ = tx.send(UiMessage::Done { log });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(UiMessage::Error { err: e.to_string() });
                                        }
                                    }
                                } else {
                                    let res = reveal_to_dir(&stego_clone, &outdir, 2, pw, Some(cb));
                                    match res {
                                        Ok(info) => {
                                            let mut total: f64 = 0.0;
                                            for p in &info.output_paths {
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
                                            let log = format!(
                                                "OK: {} ficheiro(s) → {} (encrypted={}, multi={}) | {:.2}s | {:.2} MiB/s",
                                                info.output_paths.len(),
                                                outdir.display(),
                                                info.encrypted,
                                                info.multi,
                                                dt,
                                                mbps,
                                            );
                                            let _ = tx.send(UiMessage::Done { log });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(UiMessage::Error { err: e.to_string() });
                                        }
                                    }
                                }
                            });
                        } else {
                            self.push_log("ERRO: escolhe stego.");
                        }
                    }
                });
            });

            right.vertical(|ui| {
                section_frame(ui, "Juntar partes (container)", |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Adicionar partes...").clicked() {
                            if let Some(paths) = rfd::FileDialog::new()
                                .add_filter("PNG", &["png"])
                                .pick_files()
                            {
                                for p in paths {
                                    if !self.join_parts.contains(&p) {
                                        self.join_parts.push(p);
                                    }
                                }
                            }
                        }
                        if ui.button("Limpar lista").clicked() {
                            self.join_parts.clear();
                        }
                    });
                    egui::ScrollArea::vertical()
                        .max_height(140.0)
                        .show(ui, |ui| {
                            if self.join_parts.is_empty() {
                                ui.label("(sem partes selecionadas)");
                            } else {
                                for p in &self.join_parts {
                                    ui.label(p.display().to_string());
                                }
                            }
                        });
                    ui.horizontal(|ui| {
                        ui.label("Saída (ficheiro):");
                        let mut out_txt = self
                            .join_out
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        let response = ui.text_edit_singleline(&mut out_txt);
                        if response.lost_focus() && !out_txt.is_empty() {
                            self.join_out = Some(PathBuf::from(out_txt.trim()));
                        }
                        if ui.button("Escolher...").clicked() {
                            if let Some(path) = rfd::FileDialog::new().save_file() {
                                self.join_out = Some(path);
                            }
                        }
                    });
                    if ui.add_enabled(!self.busy, egui::Button::new("Juntar partes")).clicked() {
                        if self.join_parts.is_empty() {
                            self.push_log("ERRO: adiciona partes PNG.");
                            return;
                        }
                        let out = self.join_out.clone().unwrap_or_else(|| PathBuf::from("joined.bin"));
                        let pw =
                            if self.password.is_empty() { None } else { Some(self.password.clone()) };
                        let parts = self.join_parts.clone();
                        self.push_log(&format!(
                            "A iniciar join: partes={}, out='{}', password_set={}",
                            parts.len(),
                            out.display(),
                            pw.is_some()
                        ));
                        self.busy = true;
                        self.progress_value = 0.0;
                        let (tx, rx) = mpsc::channel();
                        self.rx = Some(rx);
                        thread::spawn(move || {
                            let ticker_flag = start_prepare_ticker(tx.clone(), "A preparar (ler/decifrar)");
                            let t0 = Instant::now();
                            let tx_progress = tx.clone();
                            let cb = Arc::new(move |p: ProgressUpdate| {
                                let _ = tx_progress.send(UiMessage::Progress {
                                    label: "A juntar".into(),
                                    update: p,
                                });
                            });
                            ticker_flag.store(false, Ordering::Relaxed);
                            let res = join_container_png_parts_to_file(&parts, &out, pw.as_deref(), Some(cb));
                            match res {
                                Ok(()) => {
                                    let total =
                                        std::fs::metadata(&out).map(|m| m.len() as f64).unwrap_or(0.0);
                                    let dt = t0.elapsed().as_secs_f64();
                                    let mbps = if dt > 0.0 {
                                        total / (1024.0 * 1024.0) / dt
                                    } else {
                                        0.0
                                    };
                                    let log = format!(
                                        "OK: {} | {:.2}s | {:.2} MiB/s",
                                        out.display(),
                                        dt,
                                        mbps
                                    );
                                    let _ = tx.send(UiMessage::Done { log });
                                }
                                Err(e) => {
                                    let _ = tx.send(UiMessage::Error { err: e.to_string() });
                                }
                            }
                        });
                    }
                });
            });
        });
    }

    fn ui_capacity_hint(&mut self, ui: &mut egui::Ui) {
        if self.container_mode {
            if self.files.is_empty() {
                return;
            }
            let total_in: u64 = self
                .files
                .iter()
                .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
                .sum();
            let encrypted = !self.password.is_empty();
            // overhead conservador: header+sha+nonce+salt+footer+tags (se cifrado)
            let tags = if encrypted {
                (total_in / STREAM_CHUNK) + 1
            } else {
                0
            };
            let overhead = 256u64 + tags.saturating_mul(TAG_SIZE);
            ui.horizontal_wrapped(|ui| {
                ui.label("Modo container:");
                ui.label(format!("Entrada: {}", fmt_size(total_in)));
                ui.label(format!("PNG est: ~{}", fmt_size(total_in.saturating_add(overhead))));
            });
            ui.label("Não precisa de capa grande; a imagem é só “capa” e os dados vão anexados ao PNG.");
            return;
        }

        let Some(cover) = &self.cover else {
            return;
        };
        let dims = image::image_dimensions(cover).ok();
        let (w, h) = dims.unwrap_or((0, 0));
        let cap_bytes = if w > 0 && h > 0 {
            (w as u64)
                .saturating_mul(h as u64)
                .saturating_mul(3)
                .saturating_mul(self.bpc as u64)
                / 8
        } else {
            0
        };

        let mut plain_est: u64 = 0;
        if !self.files.is_empty() {
            if self.files.len() == 1 {
                let p = &self.files[0];
                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                let name_len = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned().len() as u64)
                    .unwrap_or(12);
                plain_est = 1 + 2 + name_len + 8 + 32 + size;
            } else {
                plain_est = 1 + 4;
                for p in &self.files {
                    let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let name_len = p
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned().len() as u64)
                        .unwrap_or(12);
                    plain_est = plain_est.saturating_add(2 + name_len + 8 + 32 + size);
                }
            }
        }

        let encrypted = !self.password.is_empty();
        let cipher_est = if encrypted {
            let tag_blocks = (plain_est / STREAM_CHUNK) + 1;
            plain_est.saturating_add(tag_blocks.saturating_mul(TAG_SIZE))
        } else {
            plain_est
        };

        let header_fixed: u64 = (4 + 1 + 1 + 1 + 1 + 1 + 12 + 8 + 8) as u64;
        let salt_est: u64 = if encrypted { 22 } else { 0 };
        let total_embed_est = header_fixed + salt_est + cipher_est;
        let fits = cap_bytes > 0 && total_embed_est <= cap_bytes;

        ui.horizontal_wrapped(|ui| {
            if w > 0 && h > 0 {
                ui.label(format!("Capa: {}x{}", w, h));
            }
            ui.label(format!("Cap (bpc={}): ~{}", self.bpc, fmt_size(cap_bytes)));
            if plain_est > 0 {
                ui.label(format!("Payload est: ~{}", fmt_size(total_embed_est)));
                ui.label(format!("Cabe: {}", if fits { "sim" } else { "não" }));
            }
        });
        if !fits && plain_est > 0 {
            ui.label("Sugestões: usa uma capa maior (mais píxeis), aumenta bpc (até 4), ou reduz o ficheiro.");
        }
    }

    fn ui_help(&mut self, ui: &mut egui::Ui) {
        section_frame(ui, "Ajuda", |ui| {
            ui.collapsing("Programa", |ui| {
                ui.label("f2png converte ficheiros em dados escondidos em PNG via esteganografia LSB.");
            });
            ui.collapsing("LSB", |ui| {
                ui.label("Usa bits menos significativos dos canais R,G,B. Mais BPC = mais capacidade, mais ruído.");
            });
            ui.collapsing("BPC", |ui| {
                ui.label("1-2 bits: quase invisível; 3-4 bits: mais capacidade mas pode gerar artefactos.");
            });
            ui.collapsing("Cifra / Password", |ui| {
                ui.label("Password ativa Argon2id + ChaCha20-Poly1305 para confidencialidade e integridade.");
            });
            ui.collapsing("Multi-ficheiro", |ui| {
                ui.label("Empacota vários ficheiros com nome/tamanho/SHA. No reveal, extrai tudo para um diretório.");
            });
            ui.collapsing("Upscale", |ui| {
                ui.label("Se o payload não couber, aumenta a imagem mantendo proporção (filtro Triangle/bilinear).");
            });
            ui.collapsing("Swap-cover (CLI)", |ui| {
                ui.label("Extrai payload de um stego e re-embed noutra capa sem os ficheiros originais.");
            });
            ui.collapsing("Boas práticas", |ui| {
                ui.label("Usa PNG ou formato sem compressão destrutiva; evita reencode; guarda o BPC usado; usa password para dados sensíveis.");
            });
        });
    }

    fn ui_tests(&mut self, ui: &mut egui::Ui) {
        section_frame(ui, "Testes rápidos", |ui| {
            ui.label("Corre um roundtrip de 1 MiB e mede throughput (usa diretório temporário).");
            if ui.add_enabled(!self.busy, egui::Button::new("Correr autoteste")).clicked() {
                self.busy = true;
                self.progress_value = 0.0;
                let (tx, rx) = mpsc::channel();
                self.rx = Some(rx);
                thread::spawn(move || {
                    let dir = std::env::temp_dir().join("f2png_gui_test");
                    let _ = std::fs::create_dir_all(&dir);
                    let cover = dir.join("cover.png");
                    let infile = dir.join("test.bin");
                    let stego = dir.join("stego.png");
                    let outdir = dir.join("out");
                    // cria capa 512x512
                    let img = image::ImageBuffer::from_pixel(512, 512, image::Rgba([200, 200, 200, 255]));
                    let _ = image::DynamicImage::ImageRgba8(img).save(&cover);
                    // ficheiro 1 MiB
                    let _ = std::fs::write(&infile, vec![7u8; 1024 * 1024]);
                    let opts = EncryptOptions { password: None, bpc: 2, allow_upscale: true };
                    let t0 = Instant::now();
                    let tx_embed = tx.clone();
                    let cb_embed: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(move |p| {
                        let _ = tx_embed.send(UiMessage::Progress {
                            label: "Testar (embed)".into(),
                            update: p,
                        });
                    });
                    let _ = embed_single_file(&cover, &infile, &stego, &opts, Some(cb_embed));
                    let tx_reveal = tx.clone();
                    let cb_reveal: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(move |p| {
                        let _ = tx_reveal.send(UiMessage::Progress {
                            label: "Testar (reveal)".into(),
                            update: p,
                        });
                    });
                    let res = reveal_to_dir(&stego, &outdir, 2, None, Some(cb_reveal));
                    match res {
                        Ok(info) => {
                            let dt = t0.elapsed().as_secs_f64();
                            let mut total: f64 = 0.0;
                            for p in &info.output_paths {
                                if let Ok(m) = std::fs::metadata(p) {
                                    total += m.len() as f64;
                                }
                            }
                            let mbps = if dt > 0.0 { total / (1024.0 * 1024.0) / dt } else { 0.0 };
                            let log = format!(
                                "TESTE OK: {} ficheiro(s), {:.2} MiB/s, tempo {:.2}s. Saída em {}",
                                info.output_paths.len(),
                                mbps,
                                dt,
                                outdir.display()
                            );
                            let _ = tx.send(UiMessage::Done { log });
                        }
                        Err(e) => {
                            let _ = tx.send(UiMessage::Error { err: format!("Teste falhou: {}", e) });
                        }
                    }
                });
            }

            ui.separator();
            ui.heading("Benchmark sintético");
            ui.label("Gera ficheiro de 16 MiB, embebe e reporta throughput.");
            if ui.add_enabled(!self.busy, egui::Button::new("Correr benchmark 16 MiB")).clicked() {
                self.busy = true;
                self.progress_value = 0.0;
                let (tx, rx) = mpsc::channel();
                self.rx = Some(rx);
                thread::spawn(move || {
                    let dir = std::env::temp_dir().join("f2png_gui_bench");
                    let _ = std::fs::create_dir_all(&dir);
                    let cover = dir.join("bench_cover.png");
                    let infile = dir.join("bench_input.bin");
                    let stego = dir.join("bench_output.png");
                    // capa 1024x1024
                    let img = image::ImageBuffer::from_pixel(1024, 1024, image::Rgba([180, 180, 180, 255]));
                    let _ = image::DynamicImage::ImageRgba8(img).save(&cover);
                    // ficheiro 16 MiB
                    let _ = std::fs::write(&infile, vec![0u8; 16 * 1024 * 1024]);
                    let opts = EncryptOptions { password: None, bpc: 2, allow_upscale: true };
                    let t0 = Instant::now();
                    let tx_progress = tx.clone();
                    let cb = Arc::new(move |p: ProgressUpdate| {
                        let _ = tx_progress.send(UiMessage::Progress {
                            label: "Benchmark (embed)".into(),
                            update: p,
                        });
                    });
                    let res = embed_single_file(&cover, &infile, &stego, &opts, Some(cb));
                    match res {
                        Ok(info) => {
                            let dt = t0.elapsed().as_secs_f64();
                            let size = 16.0 * 1024.0 * 1024.0;
                            let mbps = if dt > 0.0 { size / (1024.0 * 1024.0) / dt } else { 0.0 };
                            let log = format!(
                                "BENCH OK: 16 MiB → {} ({}x{}), {:.2} MiB/s, {:.2}s",
                                stego.display(), info.out_width, info.out_height, mbps, dt
                            );
                            let _ = tx.send(UiMessage::Done { log });
                        }
                        Err(e) => {
                            let _ = tx.send(UiMessage::Error { err: format!("Benchmark falhou: {}", e) });
                        }
                    }
                });
            }

            ui.separator();
            ui.heading("Tabela de estimativas");
            ui.label("Corre um benchmark de 16 MiB e gera tabela de tempos.");
            if ui.add_enabled(!self.busy, egui::Button::new("Gerar tabela de estimativas")).clicked() {
                self.busy = true;
                self.progress_value = 0.0;
                let (tx, rx) = mpsc::channel();
                self.rx = Some(rx);
                thread::spawn(move || {
                    let dir = std::env::temp_dir().join("f2png_gui_bench_table");
                    let _ = std::fs::create_dir_all(&dir);
                    let cover = dir.join("bench_cover.png");
                    let infile = dir.join("bench_input.bin");
                    let stego = dir.join("bench_output.png");
                    // capa 1024x1024
                    let img = image::ImageBuffer::from_pixel(1024, 1024, image::Rgba([180, 180, 180, 255]));
                    let _ = image::DynamicImage::ImageRgba8(img).save(&cover);
                    // ficheiro 16 MiB
                    let size: u64 = 16 * 1024 * 1024;
                    let _ = std::fs::write(&infile, vec![0u8; size as usize]);
                    let opts = EncryptOptions { password: None, bpc: 2, allow_upscale: true };
                    let t0 = Instant::now();
                    let tx_progress = tx.clone();
                    let cb = Arc::new(move |p: ProgressUpdate| {
                        let _ = tx_progress.send(UiMessage::Progress {
                            label: "Benchmark (tabela)".into(),
                            update: p,
                        });
                    });
                    let res = embed_single_file(&cover, &infile, &stego, &opts, Some(cb));
                    match res {
                        Ok(_info) => {
                            let dt = t0.elapsed().as_secs_f64();
                            let mib_s = if dt > 0.0 { (size as f64) / (1024.0 * 1024.0) / dt } else { 0.0 };
                            let sizes = size_list();
                            let out_path = PathBuf::from("output/bench_estimates_gui.txt");
                            if let Some(parent) = out_path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let mut buf = String::new();
                            buf.push_str("# Estimativa de tempos para f2png (GUI)\n");
                            buf.push_str(&format!(
                                "# Benchmark real: esconder {} a ~{:.2} MiB/s\n",
                                fmt_size(size),
                                mib_s
                            ));
                            buf.push_str("# Formato: tamanho_bytes\tTamanho_humano\tSegundos_est\tTempo_humano\n\n");
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
                            let _ = std::fs::write(&out_path, buf);
                            let log = format!(
                                "TABELA OK: {:.2} MiB/s | {:.2}s | escrito em {}",
                                mib_s,
                                dt,
                                out_path.display()
                            );
                            let _ = tx.send(UiMessage::Done { log });
                        }
                        Err(e) => {
                            let _ = tx.send(UiMessage::Error { err: format!("Tabela/benchmark falhou: {}", e) });
                        }
                    }
                });
            }
        });
    }
}

fn file_picker(ui: &mut egui::Ui, label: &str, target: &mut Option<PathBuf>, image_only: bool) {
    ui.horizontal(|ui| {
        if ui.button(label).clicked() {
            let mut dialog = rfd::FileDialog::new();
            if image_only {
                dialog = dialog.add_filter("Imagem", &["png", "jpg", "jpeg"]);
            }
            if let Some(path) = dialog.pick_file() {
                *target = Some(path);
            }
        }
        ui.label(
            target
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or("(nenhum)".into()),
        );
    });
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
