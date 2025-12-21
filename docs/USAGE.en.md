# f2png - Usage Guide (EN)

## Overview

f2png has two main modes:

- LSB: hides data in least-significant bits (needs a cover image large enough).
- Container: appends the file to a PNG (no LSB), ideal for large files.

Container mode can split into parts (each PNG below a limit, e.g. 2 GiB) and re-join later.

## CLI

### General help

```
cargo run -p f2png-cli -- --help
```

### Benchmarks (timing table)

```
# LSB (embed)
cargo run -p f2png-cli -- bench --size 16777216 --bpc 2 --out output/bench_estimates.txt

# LSB (embed) with password
cargo run -p f2png-cli -- bench --size 16777216 --bpc 2 --out output/bench_estimates.txt --password optional

# Container (embed)
cargo run -p f2png-cli -- bench-container-embed --size 16777216 --out output/bench_container_embed.txt --password optional

# Container (reveal)
cargo run -p f2png-cli -- bench-container-reveal --size 16777216 --out output/bench_container_reveal.txt --password optional
```

### LSB (embed/reveal)

```
# hide a single file
cargo run -p f2png-cli -- embed cover.png file.bin stego.png --bpc 2 --password optional

# hide multiple files
cargo run -p f2png-cli -- embed-multi cover.png stego.png file1.bin file2.bin --bpc 2 --password optional

# reveal
cargo run -p f2png-cli -- reveal stego.png --bpc 2 --password optional --outdir out
```

Notes:
- `--bpc` controls capacity vs visual noise (1..=4).
- `--password` enables encryption (Argon2id + ChaCha20-Poly1305).
- `--allow-upscale` lets the cover image upscale to fit the payload.

### Container (single file)

```
# create container
cargo run -p f2png-cli -- container-embed cover.png bigfile.bin container.png --password optional

# reveal container
cargo run -p f2png-cli -- container-reveal container.png --password optional --outdir out
```

### Container split (< limit)

```
# split using a binary preset
cargo run -p f2png-cli -- container-embed-split cover.png bigfile.bin outdir --max-gib 2 --password optional

# split with manual bytes
cargo run -p f2png-cli -- container-embed-split cover.png bigfile.bin outdir --max-bytes 2147483648 --password optional
```

Parts are named `name_part0001.png`, `name_part0002.png`, etc.
Presets: 2/4/8/16/32/64/128 GiB (binary).

### Split an existing container

```
cargo run -p f2png-cli -- container-split container.png cover.png outdir --max-gib 2 --password optional
```

Note: this extracts the file and re-embeds the parts using the chosen cover.

### Join parts

```
# pass parts explicitly
cargo run -p f2png-cli -- container-join output.bin outdir/*.png --password optional

# or use a folder
cargo run -p f2png-cli -- container-join output.bin --indir outdir --password optional
```

## GUI

### Hide file(s)

1) Pick cover image.
2) Add file(s).
3) Enable "Container mode" for large files.
4) To split, enable "Split into parts" and set the limit.
5) Set password (optional).
6) Click "Hide → PNG".

### Reveal

1) Pick stego image.
2) Choose output folder.
3) For container parts, enable "Split container into parts", choose cover and limit.
4) Click "Reveal".

### Join parts

1) Add PNG parts.
2) Choose output file.
3) Click "Join parts".

## Tips and best practices

- Use PNG or other lossless formats.
- Keep the `--bpc` value.
- Avoid re-encoding to JPEG.
- Use a password for sensitive data.

## Troubleshooting

- "Password required": the payload is encrypted.
- "SHA mismatch": wrong password or missing parts.
- If the output PNG exceeds the limit, lower the max size.
