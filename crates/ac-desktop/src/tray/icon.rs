pub const SIZES: [u32; 4] = [16, 22, 32, 48];

/// What the Windows tray is handed. It takes one image and scales it itself.
#[cfg(target_os = "windows")]
pub const NATIVE: u32 = 32;

pub fn rgba(size: u32) -> Vec<u8> {
    let side = size as f32;
    let radius = side * 0.24;
    let inset = (side * 0.06).max(1.0);

    let (br, bg, bb) = (0x25u8, 0x63u8, 0xebu8);

    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let (mut cover, mut bar) = (0.0f32, 0.0f32);
            for (dx, dy) in [(0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)] {
                let px = x as f32 + dx;
                let py = y as f32 + dy;
                if inside_round_rect(px, py, inset, side - inset, radius) {
                    cover += 0.25;
                    if inside_bars(px, py, side) {
                        bar += 0.25;
                    }
                }
            }

            if cover <= 0.0 {
                out.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let mix = |channel: u8| -> u8 {
                let base = channel as f32;
                let lit = base + (255.0 - base) * 0.92;
                (base * (1.0 - bar) + lit * bar).round().clamp(0.0, 255.0) as u8
            };

            out.extend_from_slice(&[
                mix(br),
                mix(bg),
                mix(bb),
                (cover * 255.0).round().clamp(0.0, 255.0) as u8,
            ]);
        }
    }
    out
}

#[cfg(target_os = "linux")]
pub fn argb(size: u32) -> Vec<u8> {
    rgba(size)
        .chunks_exact(4)
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect()
}

fn inside_round_rect(x: f32, y: f32, lo: f32, hi: f32, radius: f32) -> bool {
    if x < lo || x > hi || y < lo || y > hi {
        return false;
    }
    // Only the corners need the distance check; the straight edges are already in.
    let cx = if x < lo + radius {
        lo + radius
    } else if x > hi - radius {
        hi - radius
    } else {
        return true;
    };
    let cy = if y < lo + radius {
        lo + radius
    } else if y > hi - radius {
        hi - radius
    } else {
        return true;
    };
    let (dx, dy) = (x - cx, y - cy);
    dx * dx + dy * dy <= radius * radius
}

/// Two bars, the lower one short. Two rather than three, and thick rather than fine, because
/// at 16px a third bar closes the gaps and the whole mark turns into a block.
fn inside_bars(x: f32, y: f32, side: f32) -> bool {
    let thickness = (side * 0.15).max(2.0);
    let left = side * 0.28;
    for (i, right) in [0.72, 0.55].into_iter().enumerate() {
        let top = side * (0.33 + 0.26 * i as f32);
        if y >= top && y < top + thickness && x >= left && x < side * right {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which pixels are opaque, and which of those are part of a bar, per row.
    fn rows(size: u32) -> Vec<(usize, usize)> {
        let px = rgba(size);
        (0..size)
            .map(|y| {
                let mut solid = 0;
                let mut lit = 0;
                for x in 0..size {
                    let i = ((y * size + x) * 4) as usize;
                    if px[i + 3] > 128 {
                        solid += 1;
                        // Bars are near-white; the background is the accent blue.
                        if px[i] > 150 {
                            lit += 1;
                        }
                    }
                }
                (solid, lit)
            })
            .collect()
    }

    #[test]
    fn every_offered_size_is_the_size_it_claims() {
        for size in SIZES {
            assert_eq!(rgba(size).len(), (size * size * 4) as usize, "at {size}px");
        }
    }

    #[test]
    fn the_corners_are_clear_and_the_middle_is_not() {
        for size in SIZES {
            let px = rgba(size);
            let alpha = |x: u32, y: u32| px[((y * size + x) * 4 + 3) as usize];

            assert_eq!(
                alpha(0, 0),
                0,
                "a rounded icon leaves its corners empty, at {size}px"
            );
            assert_eq!(alpha(size - 1, size - 1), 0, "at {size}px");
            assert_eq!(
                alpha(size / 2, size / 2),
                255,
                "and is solid inside, at {size}px"
            );
        }
    }

    #[test]
    fn both_bars_survive_at_every_size() {
        // The bug this guards: a mark that looks right at 32px and turns into one smudge at
        // the size a panel actually asks for. Bars must be separated by unlit rows.
        for size in SIZES {
            let lit: Vec<bool> = rows(size).iter().map(|(_, lit)| *lit > 0).collect();

            let bands = lit.windows(2).filter(|w| w[0] != w[1]).count();
            assert_eq!(
                bands, 4,
                "expected two separated bars at {size}px, saw {bands} edges in {lit:?}"
            );
        }
    }

    #[test]
    fn the_lower_bar_is_the_shorter_one() {
        // What makes the mark read as a stack rather than an equals sign.
        let size = 32;
        let widths: Vec<usize> = rows(size)
            .into_iter()
            .map(|(_, lit)| lit)
            .filter(|lit| *lit > 0)
            .collect();

        let first = widths.first().copied().unwrap_or(0);
        let last = widths.last().copied().unwrap_or(0);
        assert!(
            last < first,
            "lower bar {last} should be shorter than upper {first}"
        );
    }
}
