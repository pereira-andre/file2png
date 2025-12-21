# f2png — Rust LSB Stego (CLI + GUI)

[![CI](https://github.com/pereira-andre/file2png/actions/workflows/ci.yml/badge.svg)](https://github.com/pereira-andre/file2png/actions/workflows/ci.yml)

Rust workspace que substitui a versao Python original, com foco em performance, cifra moderna e app nativa.

- Docs PT: `docs/USAGE.pt.md`
- Docs EN: `docs/USAGE.en.md`

## Estrutura

- `crates/f2png-core`: nucleo LSB com Argon2id + ChaCha20-Poly1305, suporte single/multi, preserva nome/sha, progress callbacks.
- `crates/f2png-cli`: linha de comando (embed, reveal, container, split/join, swap-cover, info, help).
- `crates/f2png-gui`: GUI nativa (egui/eframe) com progress bar, logs e modos container.

## Uso rapido (PT)

Pre-requisitos: Rust toolchain.

CLI:
```
cargo run -p f2png-cli -- --help
cargo run -p f2png-cli -- embed cover.png ficheiro.bin stego.png --bpc 2 --password opcional
cargo run -p f2png-cli -- reveal stego.png --bpc 2 --password opcional --outdir out
cargo run -p f2png-cli -- container-embed cover.png ficheiro-grande.bin container.png --password opcional
cargo run -p f2png-cli -- container-embed-split cover.png ficheiro-grande.bin outdir --max-gib 2 --password opcional
cargo run -p f2png-cli -- container-reveal container.png --password opcional --outdir out
cargo run -p f2png-cli -- container-split container.png cover.png outdir --max-gib 2 --password opcional
cargo run -p f2png-cli -- container-join saida.bin outdir/*.png --password opcional
```

GUI:
```
cargo run -p f2png-gui
```
Painel de progresso no topo e logs no fundo. O modo container suporta dividir em partes e juntar partes.

## Quick Start (EN)

Prerequisites: Rust toolchain.

CLI:
```
cargo run -p f2png-cli -- --help
cargo run -p f2png-cli -- embed cover.png file.bin stego.png --bpc 2 --password optional
cargo run -p f2png-cli -- reveal stego.png --bpc 2 --password optional --outdir out
cargo run -p f2png-cli -- container-embed cover.png bigfile.bin container.png --password optional
cargo run -p f2png-cli -- container-embed-split cover.png bigfile.bin outdir --max-gib 2 --password optional
cargo run -p f2png-cli -- container-reveal container.png --password optional --outdir out
cargo run -p f2png-cli -- container-split container.png cover.png outdir --max-gib 2 --password optional
cargo run -p f2png-cli -- container-join output.bin outdir/*.png --password optional
```

GUI:
```
cargo run -p f2png-gui
```
Top progress panel and bottom logs. Container mode supports split/join.

## Rust docs

```
cargo doc --workspace --open
```

## Contributing

See `CONTRIBUTING.md` and `SECURITY.md`.

## License

MIT. See `LICENSE`.
