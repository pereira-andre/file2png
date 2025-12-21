# Contributing

Thanks for your interest in improving f2png.

## Development setup

- Rust toolchain (stable)
- Run checks:
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p f2png-core`
  - `cargo check --workspace`

## Pull request guidelines

- Keep changes focused and well scoped.
- Include tests where it makes sense.
- Update documentation when behavior or CLI changes.
- Prefer clear commit messages.

## Reporting issues

Please include:
- OS and Rust version
- Steps to reproduce
- Expected vs. actual behavior
- Sample files or minimal repro if possible
