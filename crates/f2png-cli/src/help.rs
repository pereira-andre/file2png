use std::collections::HashMap;

pub fn topics() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert(
        "programa",
        "f2png converte ficheiros em dados escondidos numa imagem PNG via LSB. \
Pode cifrar o payload com Argon2id + ChaCha20-Poly1305 e suporta multi-ficheiro.",
    );
    m.insert(
        "lsb",
        "LSB usa bits menos significativos dos canais R,G,B para escrever dados. \
Mais bits por canal = mais capacidade, mais ruído.",
    );
    m.insert(
        "bpc",
        "Bits por canal (1..=4). 1-2 quase invisível; 3-4 aumenta capacidade mas pode gerar artefactos visuais.",
    );
    m.insert(
        "upscale",
        "Upscale automático aumenta a resolução da imagem de cobertura para caber o payload mantendo proporção.",
    );
    m.insert(
        "crypto",
        "Quando defines password, usa Argon2id para derivar chave (memória-hard) e ChaCha20-Poly1305 para AEAD.",
    );
    m.insert(
        "multi",
        "Multi-ficheiro empacota vários ficheiros com nome, tamanho e SHA individuais. No reveal, extrai tudo para um diretório.",
    );
    m.insert(
        "swap-cover",
        "swap-cover extrai o payload de uma imagem stego e re-embed em outra capa sem precisar dos ficheiros originais.",
    );
    m.insert(
        "boas-praticas",
        "Usa PNG ou formato sem compressão destrutiva; evita reencode para JPEG; guarda o BPC usado; usa password para dados sensíveis.",
    );
    m
}

pub fn print_topic(topic: Option<&str>) {
    let map = topics();
    match topic {
        None => {
            println!("Tópicos disponíveis:");
            for k in map.keys() {
                println!(" - {}", k);
            }
            println!("\nUsa: f2png help <tópico>");
        }
        Some(key) => {
            if let Some(txt) = map.get(key) {
                println!("[{}]\n{}", key, txt);
            } else {
                eprintln!("Tópico '{}' não encontrado.", key);
            }
        }
    }
}
