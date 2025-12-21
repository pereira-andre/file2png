//! f2png-gui - Native GUI for f2png (egui/eframe).
//!
//! PT: Executa `cargo run -p f2png-gui`.
//! EN: Run `cargo run -p f2png-gui`.
mod ui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 780.0]),
        ..Default::default()
    };

    eframe::run_native(
        "f2png – Stego & Crypto",
        native_options,
        Box::new(|cc| Box::new(ui::F2PngApp::new(cc))),
    )
}
