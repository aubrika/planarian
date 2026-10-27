//! The indicator's icon: the identity kit's micro mark (the variant drawn for
//! 16–32 px, with larger eye cutouts), white for the dark panel, with a small
//! dot for the state: none when all is well, blue-grey while working, amber
//! for attention, red for a fault. Rendered here as ARGB pixmaps, so it needs
//! no icon theme and keeps the eye cutouts transparent.

use crate::state::Level;
use tiny_skia::{Color, FillRule, Paint, PathBuilder, Pixmap, Stroke, Transform};

const MARK: &str = include_str!("../../../assets/identity/marks/planarian-mark-micro-currentcolor.svg");
/// Sizes panels ask for.
pub const SIZES: [u32; 6] = [16, 22, 24, 32, 48, 64];

/// The mark's path in its 1024-square box (absolute M, C and Z only).
fn mark_path() -> Option<tiny_skia::Path> {
    let start = MARK.find(" d=\"")? + 4;
    let d = &MARK[start..start + MARK[start..].find('"')?];
    let mut b = PathBuilder::new();
    let mut nums: Vec<f32> = vec![];
    let mut cmd = ' ';
    let flush = |cmd: char, nums: &mut Vec<f32>, b: &mut PathBuilder| -> Option<()> {
        match cmd {
            'M' if nums.len() == 2 => b.move_to(nums[0], nums[1]),
            'C' if nums.len().is_multiple_of(6) => {
                for c in nums.chunks(6) {
                    b.cubic_to(c[0], c[1], c[2], c[3], c[4], c[5]);
                }
            }
            'Z' | ' ' if nums.is_empty() => {}
            _ => return None,
        }
        nums.clear();
        Some(())
    };
    for tok in d.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty()) {
        let first = tok.chars().next()?;
        if first.is_ascii_alphabetic() {
            flush(cmd, &mut nums, &mut b)?;
            if first == 'Z' {
                b.close();
            }
            cmd = first;
            if tok.len() > 1 {
                nums.push(tok[1..].parse().ok()?);
            }
        } else {
            nums.push(tok.parse().ok()?);
        }
    }
    flush(cmd, &mut nums, &mut b)?;
    b.finish()
}

fn dot_color(level: Level) -> Option<Color> {
    match level {
        Level::Ok => None,
        Level::Working => Some(Color::from_rgba8(0x8f, 0xb0, 0xd8, 0xff)),
        Level::Attention => Some(Color::from_rgba8(0xe0, 0xa4, 0x3a, 0xff)),
        Level::Fault => Some(Color::from_rgba8(0xe0, 0x52, 0x4f, 0xff)),
    }
}

/// The icon at `size` px, as ARGB32 in network byte order (what the
/// StatusNotifierItem `IconPixmap` property carries), not premultiplied.
pub fn render(level: Level, size: u32) -> Option<(u32, u32, Vec<u8>)> {
    let mut px = Pixmap::new(size, size)?;
    let s = size as f32;
    let mut paint = Paint { anti_alias: true, ..Paint::default() };
    paint.set_color(Color::WHITE);
    let path = mark_path()?;
    px.fill_path(&path, &paint, FillRule::EvenOdd, Transform::from_scale(s / 1024.0, s / 1024.0), None);
    if let Some(c) = dot_color(level) {
        // Lower right, ringed in the panel's charcoal so it reads on the white body.
        let r = (s * 0.2).max(3.0);
        let (cx, cy) = (s - r - s * 0.02, s - r - s * 0.02);
        let dot = PathBuilder::from_circle(cx, cy, r)?;
        paint.set_color(c);
        px.fill_path(&dot, &paint, FillRule::Winding, Transform::identity(), None);
        paint.set_color(Color::from_rgba8(0x15, 0x17, 0x19, 0xff));
        let ring = Stroke { width: (s * 0.06).max(1.0), ..Stroke::default() };
        px.stroke_path(&dot, &paint, &ring, Transform::identity(), None);
    }
    let mut argb = Vec::with_capacity((size * size * 4) as usize);
    for p in px.pixels() {
        let c = p.demultiply();
        argb.extend_from_slice(&[c.alpha(), c.red(), c.green(), c.blue()]);
    }
    Some((size, size, argb))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(icon: &(u32, u32, Vec<u8>), x: u32, y: u32) -> [u8; 4] {
        let i = ((y * icon.0 + x) * 4) as usize;
        icon.2[i..i + 4].try_into().unwrap()
    }

    #[test]
    fn the_mark_parses_and_draws_white_with_transparent_corners() {
        assert!(mark_path().is_some());
        let ok = render(Level::Ok, 64).unwrap();
        assert_eq!(ok.2.len(), 64 * 64 * 4);
        assert_eq!(at(&ok, 0, 0)[0], 0, "corner is transparent");
        // Some opaque white pixels (the body), none coloured.
        let white = ok.2.chunks(4).filter(|p| p[0] == 255 && p[1] == 255 && p[2] == 255 && p[3] == 255).count();
        assert!(white > 64 * 64 / 10, "{white} white pixels");
        assert!(ok.2.chunks(4).all(|p| p[0] == 0 || (p[1] == p[2] && p[2] == p[3])), "monochrome when ok");
    }

    /// `PLANARIAN_TRAY_DUMP=dir cargo test -p planarian-tray`: writes each
    /// state's 64 px icon as raw RGBA (`convert -size 64x64 -depth 8 rgba:f f.png`).
    #[test]
    fn dump_for_inspection() {
        let Ok(dir) = std::env::var("PLANARIAN_TRAY_DUMP") else { return };
        for l in [Level::Ok, Level::Working, Level::Attention, Level::Fault] {
            let (_, _, argb) = render(l, 64).unwrap();
            let rgba: Vec<u8> = argb.chunks(4).flat_map(|p| [p[1], p[2], p[3], p[0]]).collect();
            std::fs::write(format!("{dir}/{l:?}.rgba"), rgba).unwrap();
        }
    }

    #[test]
    fn the_dot_shows_the_state() {
        let r = 64.0 * 0.2;
        let c = (64.0 - r - 64.0 * 0.02) as u32;
        assert_eq!(at(&render(Level::Fault, 64).unwrap(), c, c), [0xff, 0xe0, 0x52, 0x4f]);
        assert_eq!(at(&render(Level::Attention, 64).unwrap(), c, c), [0xff, 0xe0, 0xa4, 0x3a]);
        assert_ne!(at(&render(Level::Ok, 64).unwrap(), c, c), [0xff, 0xe0, 0x52, 0x4f]);
        for s in SIZES {
            assert!(render(Level::Working, s).is_some());
        }
    }
}
