use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/tray/icon.rs"]
mod icon;

const APP: [u32; 5] = [32, 64, 128, 256, 512];

/// What goes inside the Windows `.ico`. 256 is the one Explorer uses for large icons.
const ICO: [u32; 4] = [16, 32, 48, 256];

fn main() -> std::io::Result<()> {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/icons");
    std::fs::create_dir_all(&out)?;

    for size in APP {
        let path = out.join(format!("{size}x{size}.png"));
        std::fs::write(&path, png(size)?)?;
        println!("{}", path.display());
    }

    let path = out.join("icon.ico");
    ico(&path, &ICO)?;
    println!("{}", path.display());

    Ok(())
}

/// One PNG, from the same pixels the tray is given.
fn png(size: u32) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(BufWriter::new(&mut bytes), size, size);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);

        let mut writer = encoder.write_header().map_err(std::io::Error::other)?;
        writer
            .write_image_data(&icon::rgba(size))
            .map_err(std::io::Error::other)?;
    }
    Ok(bytes)
}

/// An `.ico` holding PNG-compressed entries, which every Windows since Vista reads.
fn ico(path: &Path, sizes: &[u32]) -> std::io::Result<()> {
    let images: Vec<(u32, Vec<u8>)> = sizes
        .iter()
        .map(|&size| Ok((size, png(size)?)))
        .collect::<std::io::Result<_>>()?;

    let mut file = BufWriter::new(File::create(path)?);

    file.write_all(&0u16.to_le_bytes())?; // reserved, always zero
    file.write_all(&1u16.to_le_bytes())?; // 1 is an icon, 2 would be a cursor
    file.write_all(&(images.len() as u16).to_le_bytes())?;

    let mut offset = 6 + 16 * images.len() as u32;
    for (size, data) in &images {
        // 256 does not fit in a byte, and the format says zero means 256.
        let side = if *size >= 256 { 0u8 } else { *size as u8 };

        file.write_all(&[side, side, 0, 0])?; // width, height, palette size, reserved
        file.write_all(&1u16.to_le_bytes())?; // colour planes
        file.write_all(&32u16.to_le_bytes())?; // bits per pixel
        file.write_all(&(data.len() as u32).to_le_bytes())?;
        file.write_all(&offset.to_le_bytes())?;
        offset += data.len() as u32;
    }

    for (_, data) in &images {
        file.write_all(data)?;
    }
    file.flush()
}
