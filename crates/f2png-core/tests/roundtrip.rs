use f2png_core::{
    embed_multi, embed_single_file, info_capacity, reveal_to_dir, unwrap_container_png_to_dir,
    wrap_single_file_container_png, EncryptOptions,
};
use std::io::Write;
use tempfile::tempdir;

fn make_cover(path: &std::path::Path) {
    let img = image::ImageBuffer::from_pixel(256, 256, image::Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(path).unwrap();
}

fn make_cover_size(path: &std::path::Path, w: u32, h: u32) {
    let img = image::ImageBuffer::from_pixel(w, h, image::Rgba([200, 200, 200, 255]));
    image::DynamicImage::ImageRgba8(img).save(path).unwrap();
}

fn make_file(path: &std::path::Path, size: usize, byte: u8) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&vec![byte; size]).unwrap();
}

#[test]
fn roundtrip_single_plain() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("file.bin");
    let stego = dir.path().join("stego.png");
    let outdir = dir.path().join("out");

    make_cover(&cover);
    make_file(&infile, 128 * 1024, 7);

    let opts = EncryptOptions {
        password: None,
        bpc: 2,
        allow_upscale: true,
    };
    embed_single_file(&cover, &infile, &stego, &opts, None).unwrap();
    let res = reveal_to_dir(&stego, &outdir, 2, None, None).unwrap();
    assert_eq!(res.output_paths.len(), 1);
    let restored = std::fs::read(&res.output_paths[0]).unwrap();
    let original = std::fs::read(&infile).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn roundtrip_single_encrypted() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("file.bin");
    let stego = dir.path().join("stego.png");
    let outdir = dir.path().join("out");

    make_cover(&cover);
    make_file(&infile, 64 * 1024, 0xAB);

    let opts = EncryptOptions {
        password: Some("secret123".into()),
        bpc: 2,
        allow_upscale: true,
    };
    embed_single_file(&cover, &infile, &stego, &opts, None).unwrap();
    let res = reveal_to_dir(&stego, &outdir, 2, Some("secret123".into()), None).unwrap();
    assert_eq!(res.output_paths.len(), 1);
    let restored = std::fs::read(&res.output_paths[0]).unwrap();
    let original = std::fs::read(&infile).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn roundtrip_single_encrypted_large_stream() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("file.bin");
    let stego = dir.path().join("stego.png");
    let outdir = dir.path().join("out");

    // Cap em bpc=4: w*h*3*4/8 bytes. 2048x2048 ≈ 6.0 MiB.
    make_cover_size(&cover, 2048, 2048);
    make_file(&infile, 5 * 1024 * 1024, 0x3C);

    let opts = EncryptOptions {
        password: Some("secret123".into()),
        bpc: 4,
        allow_upscale: false,
    };
    embed_single_file(&cover, &infile, &stego, &opts, None).unwrap();
    let res = reveal_to_dir(&stego, &outdir, 4, Some("secret123".into()), None).unwrap();
    assert_eq!(res.output_paths.len(), 1);
    let restored = std::fs::read(&res.output_paths[0]).unwrap();
    let original = std::fs::read(&infile).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn roundtrip_multi_plain() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let stego = dir.path().join("stego.png");
    let outdir = dir.path().join("out");

    make_cover(&cover);
    let mut inputs = Vec::new();
    for i in 0..3 {
        let p = dir.path().join(format!("file{i}.bin"));
        make_file(&p, 32 * 1024, i as u8);
        inputs.push(p);
    }

    let opts = EncryptOptions {
        password: None,
        bpc: 2,
        allow_upscale: true,
    };
    embed_multi(&cover, &inputs, &stego, &opts, None).unwrap();
    let res = reveal_to_dir(&stego, &outdir, 2, None, None).unwrap();
    assert_eq!(res.output_paths.len(), 3);
    for (orig, restored) in inputs.iter().zip(res.output_paths.iter()) {
        assert_eq!(
            std::fs::read(orig).unwrap(),
            std::fs::read(restored).unwrap()
        );
    }
}

#[test]
fn info_capacity_matches() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    make_cover(&cover);
    let (w, h, cap) = info_capacity(&cover, 2).unwrap();
    assert_eq!((w, h), (256, 256));
    // cap = w*h*3*BPC/8
    assert_eq!(cap, (w as usize) * (h as usize) * 3 * 2 / 8);
}

#[test]
fn container_wrap_unwrap_plain() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("file.bin");
    let outpng = dir.path().join("container.png");
    let outdir = dir.path().join("out");

    make_cover(&cover);
    make_file(&infile, 256 * 1024, 0x5A);

    wrap_single_file_container_png(Some(&cover), &infile, &outpng, None, None).unwrap();
    let restored = unwrap_container_png_to_dir(&outpng, &outdir, None, None).unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), std::fs::read(&infile).unwrap());
}

#[test]
fn container_wrap_unwrap_encrypted() {
    let dir = tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let infile = dir.path().join("file.bin");
    let outpng = dir.path().join("container.png");
    let outdir = dir.path().join("out");

    make_cover(&cover);
    make_file(&infile, 512 * 1024, 0xC3);

    wrap_single_file_container_png(Some(&cover), &infile, &outpng, Some("pw123"), None).unwrap();
    let restored = unwrap_container_png_to_dir(&outpng, &outdir, Some("pw123"), None).unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), std::fs::read(&infile).unwrap());
}
