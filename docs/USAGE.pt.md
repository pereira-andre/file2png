# f2png - Guia de utilizacao (PT)

## Visao geral

O f2png tem dois modos principais:

- LSB: esconde dados nos bits menos significativos (precisa de imagem de cobertura grande o suficiente).
- Container: anexa o ficheiro ao PNG (nao usa LSB), ideal para ficheiros grandes.

O modo container pode dividir em partes (cada PNG abaixo de um limite, ex: 2 GiB) e juntar as partes depois.

## CLI

### Ajuda geral

```
cargo run -p f2png-cli -- --help
```

### Benchmarks (tabela de tempos)

```
# LSB (embed)
cargo run -p f2png-cli -- bench --size 16777216 --bpc 2 --out output/bench_estimates.txt

# LSB (embed) com password
cargo run -p f2png-cli -- bench --size 16777216 --bpc 2 --out output/bench_estimates.txt --password opcional

# Container (embed)
cargo run -p f2png-cli -- bench-container-embed --size 16777216 --out output/bench_container_embed.txt --password opcional

# Container (reveal)
cargo run -p f2png-cli -- bench-container-reveal --size 16777216 --out output/bench_container_reveal.txt --password opcional
```

### LSB (embed/reveal)

```
# esconder 1 ficheiro
cargo run -p f2png-cli -- embed cover.png ficheiro.bin stego.png --bpc 2 --password opcional

# esconder varios ficheiros
cargo run -p f2png-cli -- embed-multi cover.png stego.png ficheiro1.bin ficheiro2.bin --bpc 2 --password opcional

# revelar
cargo run -p f2png-cli -- reveal stego.png --bpc 2 --password opcional --outdir out
```

Notas:
- `--bpc` controla capacidade e ruido visual (1..=4).
- `--password` ativa cifra (Argon2id + ChaCha20-Poly1305).
- `--allow-upscale` permite aumentar a imagem para caber o payload.

### Container (1 ficheiro)

```
# criar container
cargo run -p f2png-cli -- container-embed cover.png ficheiro-grande.bin container.png --password opcional

# revelar container
cargo run -p f2png-cli -- container-reveal container.png --password opcional --outdir out
```

### Container com partes (< limite)

```
# criar partes (preset binario)
cargo run -p f2png-cli -- container-embed-split cover.png ficheiro-grande.bin outdir --max-gib 2 --password opcional

# criar partes (manual)
cargo run -p f2png-cli -- container-embed-split cover.png ficheiro-grande.bin outdir --max-bytes 2147483648 --password opcional
```

As partes sao geradas como `nome_part0001.png`, `nome_part0002.png`, etc.
Presets: 2/4/8/16/32/64/128 GiB (binarios).

### Separar um container ja criado

```
cargo run -p f2png-cli -- container-split container.png cover.png outdir --max-gib 2 --password opcional
```

Nota: este processo extrai o ficheiro e volta a gerar as partes com a capa escolhida.

### Juntar partes

```
# listar partes diretamente
cargo run -p f2png-cli -- container-join saida.bin outdir/*.png --password opcional

# ou usar pasta
cargo run -p f2png-cli -- container-join saida.bin --indir outdir --password opcional
```

## GUI

### Esconder ficheiro(s)

1) Escolhe a capa.
2) Adiciona ficheiro(s).
3) Ativa "Modo container" para ficheiros grandes.
4) Se quiseres dividir, ativa "Dividir em partes" e define o limite.
5) Define password (opcional).
6) Clica "Esconder → PNG".

### Revelar

1) Escolhe a imagem stego.
2) Define a pasta de destino.
3) Se for container com partes, ativa "Separar container em partes", escolhe a capa e o limite.
4) Clica "Revelar".

### Juntar partes

1) Adiciona as partes PNG.
2) Define o ficheiro de saida.
3) Clica "Juntar partes".

## Dicas e boas praticas

- Usa PNG ou formatos sem compressao destrutiva.
- Guarda o valor de `--bpc` usado.
- Evita re-encode para JPEG.
- Para dados sensiveis, usa password.

## Troubleshooting

- "Password requerida": o container/LSB foi cifrado e precisas de password.
- "SHA mismatch": password errada ou partes incompletas.
- Se o PNG final exceder o limite, reduz o tamanho maximo por parte.
