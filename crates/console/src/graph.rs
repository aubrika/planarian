//! The Graph view: units laid out in layers by dependency, each with three
//! indicators (desired, observed, health), edges styled by kind.

use crate::{MUTED, Message, RAISED, TEXT};
use iced::mouse;
use iced::widget::canvas::{self, Frame, Geometry, LineDash, Path, Stroke, Text};
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};
use planarian_ipc::{ConsoleReport, GraphNode};
use planarian_schema::{EdgeKind, UnitId, UnitStatus};
use std::collections::BTreeMap;

pub const LEGEND: &str = "Each unit shows three dots: desired · observed · health.\n\
    Lines: solid requires, dashed wants, dotted ordering only, dash-dot diagnostic.\n\
    Hatched: left alone (suppressed). Grey with a clock: no fresh evidence.";

const NODE: Size = Size::new(170.0, 46.0);

pub struct Graph<'a> {
    pub report: &'a ConsoleReport,
    pub selected: Option<&'a UnitId>,
    /// Cleared when the report or the selection changes, so animation frames
    /// elsewhere in the window do not redraw the graph.
    pub cache: &'a canvas::Cache,
}

/// Layers by longest chain of functional dependencies: a unit sits below
/// everything it requires or wants.
pub fn layout(r: &ConsoleReport, bounds: Size) -> BTreeMap<UnitId, Point> {
    let deps = |u: &UnitId| -> Vec<UnitId> {
        r.edges
            .iter()
            .filter(|e| &e.from == u && matches!(e.kind, EdgeKind::Requires | EdgeKind::Wants))
            .map(|e| e.to.clone())
            .collect()
    };
    let mut depth: BTreeMap<UnitId, usize> = r.nodes.iter().map(|n| (n.unit.clone(), 0)).collect();
    // Relax at most n times; cycles (diagnostic edges are excluded) stop growing.
    for _ in 0..r.nodes.len() {
        let mut changed = false;
        for n in &r.nodes {
            let d = deps(&n.unit).iter().filter_map(|t| depth.get(t).map(|d| d + 1)).max().unwrap_or(0);
            let cur = depth.get_mut(&n.unit).expect("node");
            if d > *cur && d <= r.nodes.len() {
                *cur = d;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut layers: BTreeMap<usize, Vec<UnitId>> = BTreeMap::new();
    for (u, d) in &depth {
        layers.entry(*d).or_default().push(u.clone());
    }
    // Each layer wraps into as many rows as the width needs; rows are evenly
    // spaced, layers separated by an extra gap.
    let per_row = (((bounds.width - GAP) / (NODE.width + GAP)).floor() as usize).max(1);
    let mut out = BTreeMap::new();
    let mut y = GAP;
    for units in layers.values() {
        for chunk in units.chunks(per_row) {
            let slot = bounds.width / chunk.len() as f32;
            for (j, u) in chunk.iter().enumerate() {
                let x = slot * j as f32 + (slot - NODE.width).max(0.0) / 2.0;
                out.insert(u.clone(), Point::new(x, y));
            }
            y += NODE.height + GAP;
        }
        y += GAP;
    }
    out
}

const GAP: f32 = 18.0;

fn health_color(s: &UnitStatus) -> Color {
    match s {
        UnitStatus::Running | UnitStatus::Bound => Color::from_rgb8(0x2e, 0x9e, 0x4f),
        UnitStatus::Degraded(_) | UnitStatus::Transitioning => Color::from_rgb8(0xe0, 0x9a, 0x1a),
        UnitStatus::Failed(_) => Color::from_rgb8(0xc8, 0x32, 0x32),
        UnitStatus::Suppressed => Color::from_rgb8(0x5a, 0x6f, 0xc0),
        UnitStatus::Stopped | UnitStatus::Absent | UnitStatus::Detected => Color::from_rgb8(0x80, 0x80, 0x80),
        UnitStatus::Unknown | UnitStatus::NotExpected => Color::from_rgb8(0xb0, 0xb0, 0xb0),
    }
}

fn observed_color(o: &str) -> Color {
    if o.starts_with("Active") || o.starts_with("Bound") {
        Color::from_rgb8(0x2e, 0x9e, 0x4f)
    } else if o.starts_with("Failed") {
        Color::from_rgb8(0xc8, 0x32, 0x32)
    } else if o.starts_with("Transitioning") {
        Color::from_rgb8(0xe0, 0x9a, 0x1a)
    } else {
        Color::from_rgb8(0xb0, 0xb0, 0xb0)
    }
}

fn desired_color(n: &GraphNode) -> Color {
    if !n.expected {
        Color::from_rgb8(0xb0, 0xb0, 0xb0)
    } else if n.desired == "Stopped" || n.desired == "Absent" {
        Color::from_rgb8(0x80, 0x80, 0x80)
    } else {
        Color::from_rgb8(0x2e, 0x9e, 0x4f)
    }
}

impl canvas::Program<Message> for Graph<'_> {
    type State = ();

    fn update(
        &self,
        _state: &mut (),
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        let canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) = event else { return None };
        let p = cursor.position_in(bounds)?;
        let pos = layout(self.report, bounds.size());
        let hit = pos.iter().find(|(_, at)| Rectangle::new(**at, NODE).contains(p))?;
        Some(canvas::Action::publish(Message::Select(hit.0.clone())))
    }

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        vec![self.cache.draw(renderer, bounds.size(), |f| self.paint(f, bounds))]
    }
}

impl Graph<'_> {
    fn paint(&self, f: &mut Frame, bounds: Rectangle) {
        let pos = layout(self.report, bounds.size());
        let center = |u: &UnitId| pos.get(u).map(|p| Point::new(p.x + NODE.width / 2.0, p.y + NODE.height / 2.0));

        for e in &self.report.edges {
            let (Some(a), Some(b)) = (center(&e.from), center(&e.to)) else { continue };
            let (segments, width, alpha): (&[f32], f32, f32) = match e.kind {
                EdgeKind::Requires => (&[], 2.0, 0.8),
                EdgeKind::Wants => (&[8.0, 5.0], 1.5, 0.7),
                EdgeKind::Ordering => (&[2.0, 4.0], 1.0, 0.5),
                EdgeKind::Diagnostic { confidence } => {
                    (&[10.0, 4.0, 2.0, 4.0], 1.5, 0.25 + 0.5 * confidence.0 as f32 / 1000.0)
                }
            };
            let stroke = Stroke {
                line_dash: LineDash { segments, offset: 0 },
                ..Stroke::default()
                    .with_color(Color { a: alpha, ..Color::from_rgb8(0xb4, 0xb8, 0xbe) })
                    .with_width(width)
            };
            f.stroke(&Path::line(a, b), stroke);
        }

        for n in &self.report.nodes {
            let Some(at) = pos.get(&n.unit) else { continue };
            let rect = Path::rounded_rectangle(*at, NODE, 6.0.into());
            let fill = if n.stale { Color::from_rgb8(0x2e, 0x31, 0x35) } else { RAISED };
            f.fill(&rect, fill);
            if n.suppressed {
                // Hatching: diagonal strokes clipped by eye to the box.
                let mut x = 0.0;
                while x < NODE.width + NODE.height {
                    let a = Point::new(at.x + x.min(NODE.width), at.y + (x - NODE.width).max(0.0));
                    let b = Point::new(at.x + (x - NODE.height).max(0.0), at.y + x.min(NODE.height));
                    f.stroke(
                        &Path::line(a, b),
                        Stroke::default().with_color(Color::from_rgba8(0x7a, 0x8f, 0xe0, 0.35)).with_width(1.0),
                    );
                    x += 9.0;
                }
            }
            let selected = self.selected == Some(&n.unit);
            f.stroke(
                &rect,
                Stroke::default()
                    .with_color(if selected { TEXT } else { Color::from_rgb8(0x4a, 0x4f, 0x56) })
                    .with_width(if selected { 2.5 } else { 1.0 }),
            );
            f.fill_text(Text {
                content: n.unit.name.clone(),
                position: Point::new(at.x + 8.0, at.y + 6.0),
                size: 14.0.into(),
                color: TEXT,
                ..Text::default()
            });
            for (i, c) in [desired_color(n), observed_color(&n.observed), health_color(&n.health)].iter().enumerate() {
                let p = Point::new(at.x + 14.0 + 16.0 * i as f32, at.y + NODE.height - 12.0);
                f.fill(&Path::circle(p, 5.0), *c);
            }
            if n.stale {
                // A small clock: no fresh evidence.
                let c = Point::new(at.x + NODE.width - 16.0, at.y + NODE.height - 14.0);
                let s = Stroke::default().with_color(MUTED).with_width(1.2);
                f.stroke(&Path::circle(c, 6.0), s);
                f.stroke(&Path::line(c, Point::new(c.x, c.y - 4.0)), s);
                f.stroke(&Path::line(c, Point::new(c.x + 3.0, c.y)), s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_ipc::{GraphEdge, StatusReport};
    use planarian_schema::GenerationId;

    fn node(name: &str) -> GraphNode {
        GraphNode {
            unit: UnitId::service(name),
            desired: "Running".into(),
            expected: true,
            observed: "Active".into(),
            health: UnitStatus::Running,
            suppressed: false,
            stale: false,
        }
    }

    #[test]
    fn dependencies_sit_above_their_dependents() {
        let status: StatusReport = serde_json::from_value(serde_json::json!({
            "generation": 1, "known_good": null, "live_tested": null, "accepted_baseline": null,
            "boot_default": null, "baseline_note": null, "units": [], "incidents": [], "pending": [],
            "in_flight": [], "interlock": [], "reconciliation": null, "notices": []
        }))
        .unwrap();
        let r = ConsoleReport {
            status,
            nodes: vec![node("app"), node("db"), node("cache")],
            edges: vec![
                GraphEdge { from: UnitId::service("app"), to: UnitId::service("db"), kind: EdgeKind::Requires },
                GraphEdge { from: UnitId::service("cache"), to: UnitId::service("app"), kind: EdgeKind::Ordering },
            ],
            timeline: vec![],
            previous: None,
            last_booted: Some(GenerationId(1)),
            candidates: vec![],
            last_change_reverted: false,
            now: Default::default(),
        };
        let p = layout(&r, Size::new(800.0, 600.0));
        assert!(p[&UnitId::service("db")].y < p[&UnitId::service("app")].y);
        // Ordering is not a dependency: cache shares the top layer with db.
        assert_eq!(p[&UnitId::service("cache")].y, p[&UnitId::service("db")].y);
    }
}
