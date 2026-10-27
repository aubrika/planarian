//! The planarian mark, drawn natively, still or in motion.
//!
//! The identity kit's `animations/keyframes.json` gives the mark as SVG path
//! strings (absolute `M`, `C` and `Z` only) in a 1024-square box, plus two
//! looping animations whose keyframes share one path structure: "loading"
//! (breathing, 3.6 s) and "working" (a counterclockwise contraction, 2.4 s).
//! Between keyframes the coordinates are interpolated linearly, as the kit
//! describes for native renderers. Three contours: the body and the two eye
//! cutouts, filled even-odd so the eyes stay transparent.

use crate::Message;
use iced::mouse;
use iced::widget::canvas::{self, Fill, Frame, Geometry, Path, fill};
use iced::{Color, Point, Rectangle, Renderer, Theme};
use std::sync::OnceLock;

const KEYFRAMES: &str = include_str!("../../../assets/identity/animations/keyframes.json");

/// One contour: a start point, then cubic segments (control 1, control 2, end).
type Contour = (Point, Vec<[Point; 3]>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    Still,
    Loading,
    Working,
}

struct Animation {
    duration: f32,
    frames: Vec<(f32, Vec<Contour>)>,
}

struct Kit {
    still: Vec<Contour>,
    loading: Animation,
    working: Animation,
}

/// Parses the kit's path strings. `None` on anything but absolute M/C/Z.
fn parse(d: &str) -> Option<Vec<Contour>> {
    let mut out: Vec<Contour> = vec![];
    let mut nums: Vec<f32> = vec![];
    let mut cmd = ' ';
    let flush = |cmd: char, nums: &mut Vec<f32>, out: &mut Vec<Contour>| -> Option<()> {
        let pts: Vec<Point> = nums.chunks(2).map(|c| Point::new(c[0], *c.get(1).unwrap_or(&0.0))).collect();
        match cmd {
            'M' => out.push((*pts.first()?, vec![])),
            'C' => {
                if pts.len() % 3 != 0 {
                    return None;
                }
                let segs = &mut out.last_mut()?.1;
                for c in pts.chunks(3) {
                    segs.push([c[0], c[1], c[2]]);
                }
            }
            ' ' | 'Z' => {}
            _ => return None,
        }
        nums.clear();
        Some(())
    };
    for tok in d.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty()) {
        let first = tok.chars().next()?;
        if first.is_ascii_alphabetic() {
            flush(cmd, &mut nums, &mut out)?;
            cmd = first;
            let rest = &tok[1..];
            if !rest.is_empty() {
                nums.push(rest.parse().ok()?);
            }
        } else {
            nums.push(tok.parse().ok()?);
        }
    }
    flush(cmd, &mut nums, &mut out)?;
    Some(out)
}

fn kit() -> &'static Option<Kit> {
    static KIT: OnceLock<Option<Kit>> = OnceLock::new();
    KIT.get_or_init(|| {
        let v: serde_json::Value = serde_json::from_str(KEYFRAMES).ok()?;
        let still = parse(v["staticPath"].as_str()?)?;
        let anim = |name: &str| -> Option<Animation> {
            let a = v["animations"].as_array()?.iter().find(|a| a["name"] == name)?;
            let frames = a["keyframes"]
                .as_array()?
                .iter()
                .map(|k| Some((k["offset"].as_f64()? as f32, parse(k["d"].as_str()?)?)))
                .collect::<Option<Vec<_>>>()?;
            Some(Animation { duration: a["durationMs"].as_f64()? as f32 / 1000.0, frames })
        };
        Some(Kit { still, loading: anim("loading")?, working: anim("working")? })
    })
}

fn lerp(a: Point, b: Point, t: f32) -> Point {
    Point::new(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t)
}

/// The mark's contours at `seconds` into the motion.
fn shape(motion: Motion, seconds: f32) -> Option<Vec<Contour>> {
    let k = kit().as_ref()?;
    let a = match motion {
        Motion::Still => return Some(k.still.clone()),
        Motion::Loading => &k.loading,
        Motion::Working => &k.working,
    };
    let phase = (seconds / a.duration).rem_euclid(1.0);
    let i = a.frames.iter().rposition(|(o, _)| *o <= phase).unwrap_or(0);
    let (o0, f0) = &a.frames[i];
    let Some((o1, f1)) = a.frames.get(i + 1) else { return Some(f0.clone()) };
    let t = if o1 > o0 { (phase - o0) / (o1 - o0) } else { 0.0 };
    // Keyframes share one structure; fall back to the nearer frame if not.
    if f0.len() != f1.len() || f0.iter().zip(f1).any(|(a, b)| a.1.len() != b.1.len()) {
        return Some(if t < 0.5 { f0.clone() } else { f1.clone() });
    }
    Some(
        f0.iter()
            .zip(f1)
            .map(|((s0, c0), (s1, c1))| {
                let segs =
                    c0.iter().zip(c1).map(|(a, b)| [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)]);
                (lerp(*s0, *s1, t), segs.collect())
            })
            .collect(),
    )
}

/// A canvas program: the mark at `seconds` into `motion`, in `color`.
pub struct Mark {
    pub motion: Motion,
    pub seconds: f32,
    pub color: Color,
}

impl canvas::Program<Message> for Mark {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut f = Frame::new(renderer, bounds.size());
        let scale = bounds.width.min(bounds.height) / 1024.0;
        let at = |p: Point| Point::new(p.x * scale, p.y * scale);
        if let Some(contours) = shape(self.motion, self.seconds) {
            let path = Path::new(|b| {
                for (start, segs) in &contours {
                    b.move_to(at(*start));
                    for [c1, c2, end] in segs {
                        b.bezier_curve_to(at(*c1), at(*c2), at(*end));
                    }
                    b.close();
                }
            });
            f.fill(&path, Fill { style: fill::Style::Solid(self.color), rule: fill::Rule::EvenOdd });
        }
        vec![f.into_geometry()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kit_parses_and_animates() {
        let k = kit().as_ref().expect("keyframes.json parses");
        assert_eq!(k.still.len(), 3, "body and two eyes");
        for a in [&k.loading, &k.working] {
            assert!(a.duration > 1.0 && a.frames.len() > 10);
        }
        let a = shape(Motion::Working, 0.3).unwrap();
        let b = shape(Motion::Working, 0.9).unwrap();
        assert_eq!(a.len(), 3);
        assert_ne!(a[0].1[5], b[0].1[5], "the body moves");
        // A cycle later it is where it was.
        let c = shape(Motion::Working, 0.3 + 2.4).unwrap();
        assert!((a[0].0.x - c[0].0.x).abs() < 0.5);
    }
}
