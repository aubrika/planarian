//! `planarian-console`: the read-only visual console (SPEC §16a).
//!
//! Views: Graph (desired, observed and health per unit as three indicators;
//! edge style by kind; suppressed units hatched; Unknown units grey with a
//! stale-clock mark), Timeline (transactions with their journal states),
//! Generations, Incidents. Buttons: undo, suppress and unsuppress, which the
//! daemon runs as Runtime transitions with the user as the actor. It reads
//! only the daemon's socket. It starts minimized unless something needs
//! attention: an open incident, a pending approval, a reconciliation record,
//! or a reverted change.

mod graph;
mod mark;

use iced::widget::{button, canvas, column, container, row, rule, scrollable, text};
use iced::{Color, Element, Fill, Subscription, Task, Theme, color, time, window};
use mark::{Mark, Motion};
use planarian_ipc::{ConsoleReport, Request, Response, SOCKET};
use planarian_schema::{IncidentState, UnitId, Until};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The identity kit's charcoal surface.
pub const SURFACE: Color = color!(0x151719);
/// A raised surface (graph nodes, panels) on the charcoal.
pub const RAISED: Color = color!(0x222529);
pub const TEXT: Color = color!(0xeceeef);
pub const MUTED: Color = color!(0x9a9fa5);

fn main() -> iced::Result {
    let icon = window::icon::from_rgba(include_bytes!("icon-64.rgba").to_vec(), 64, 64).ok();
    iced::application(Console::new, Console::update, Console::view)
        .title("planarian")
        .subscription(Console::subscription)
        .theme(Console::theme)
        .window(window::Settings {
            size: iced::Size::new(1100.0, 720.0),
            icon,
            // Matches planarian.desktop, so the shell shows the right icon.
            platform_specific: window::settings::PlatformSpecific {
                application_id: "planarian".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .run()
}

/// Dark by default: the kit is monochrome on charcoal. Status colours stay
/// (health is not identity), toned for a dark surface.
fn dark() -> Theme {
    Theme::custom(
        "planarian dark",
        iced::theme::Palette {
            background: SURFACE,
            text: TEXT,
            primary: color!(0xe8eaec),
            success: color!(0x3fb56a),
            warning: color!(0xe0a43a),
            danger: color!(0xe0524f),
        },
    )
}

/// One request to the daemon, one answer.
pub fn call(req: &Request) -> Result<Response, String> {
    let path = std::env::var("PLANARIAN_SOCKET").unwrap_or_else(|_| SOCKET.into());
    let mut s = UnixStream::connect(&path).map_err(|e| format!("{path}: {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    s.write_all(req.encode().as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("bad answer: {e}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Graph,
    Timeline,
    Generations,
    Incidents,
}

#[derive(Clone, Debug)]
enum Message {
    Tick,
    Frame,
    Show(View),
    Select(UnitId),
    Undo,
    Suppress(UnitId),
    Unsuppress(UnitId),
}

struct Console {
    view: View,
    report: Option<ConsoleReport>,
    error: Option<String>,
    selected: Option<UnitId>,
    /// The answer to the last button.
    answer: Option<String>,
    first: bool,
    /// The animation clock.
    started: Instant,
    seconds: f32,
    /// `PLANARIAN_REDUCED_MOTION=1`: show the still mark instead of motion.
    reduced_motion: bool,
    graph_cache: canvas::Cache,
}

impl Console {
    fn new() -> (Console, Task<Message>) {
        // `--view timeline|generations|incidents` opens on that view.
        let arg = std::env::args().skip_while(|a| a != "--view").nth(1).unwrap_or_default();
        let view = match arg.as_str() {
            "timeline" => View::Timeline,
            "generations" => View::Generations,
            "incidents" => View::Incidents,
            _ => View::Graph,
        };
        let reduced_motion = std::env::var("PLANARIAN_REDUCED_MOTION").is_ok_and(|v| v != "0" && !v.is_empty());
        let c = Console {
            view,
            report: None,
            error: None,
            selected: None,
            answer: None,
            first: true,
            started: Instant::now(),
            seconds: 0.0,
            reduced_motion,
            graph_cache: canvas::Cache::new(),
        };
        (c, Task::done(Message::Tick))
    }

    fn theme(&self) -> Theme {
        dark()
    }

    fn subscription(&self) -> Subscription<Message> {
        let tick = time::every(Duration::from_secs(2)).map(|_| Message::Tick);
        if self.motion() == Motion::Still || self.reduced_motion {
            tick
        } else {
            Subscription::batch([tick, time::every(Duration::from_millis(60)).map(|_| Message::Frame)])
        }
    }

    /// What the daemon is doing, if anything: "loading" while there is no
    /// answer yet, "working" while a transaction is in flight or the daemon
    /// answers from its busy snapshot.
    fn activity(&self) -> Option<(Motion, String)> {
        let Some(r) = &self.report else {
            return self.error.is_none().then(|| (Motion::Loading, "connecting to planariad…".to_string()));
        };
        let busy = r.status.notices.iter().find(|n| n.starts_with("busy with"));
        if let Some(n) = busy {
            let what = n.split(':').next().unwrap_or(n);
            return Some((Motion::Working, format!("{what}. Showing how things stood when it started.")));
        }
        r.status.in_flight.first().map(|(t, state, what)| {
            (Motion::Working, format!("working on #{}: {what} ({})", t.0, planarian_state_name(state)))
        })
    }

    fn motion(&self) -> Motion {
        self.activity().map(|a| a.0).unwrap_or(Motion::Still)
    }

    fn mark(&self, size: f32, motion: Motion) -> Element<'_, Message> {
        let motion = if self.reduced_motion { Motion::Still } else { motion };
        canvas(Mark { motion, seconds: self.seconds, color: TEXT }).width(size).height(size).into()
    }

    fn refresh(&mut self) {
        match call(&Request::Console) {
            Ok(Response::Console(r)) => {
                if self.report.as_ref() != Some(&*r) {
                    self.graph_cache.clear();
                }
                self.report = Some(*r);
                self.error = None;
            }
            Ok(other) => self.error = Some(format!("unexpected answer: {other:?}")),
            Err(e) => self.error = Some(format!("cannot reach planariad: {e}")),
        }
    }

    fn act(&mut self, req: Request) {
        self.answer = Some(match call(&req) {
            Ok(r) => describe(&r),
            Err(e) => e,
        });
        self.refresh();
    }

    fn update(&mut self, m: Message) -> Task<Message> {
        match m {
            Message::Tick => {
                self.refresh();
                if std::mem::take(&mut self.first) && !self.needs_attention() {
                    return window::latest().and_then(|id| window::minimize(id, true));
                }
            }
            Message::Frame => self.seconds = self.started.elapsed().as_secs_f32(),
            Message::Show(v) => self.view = v,
            Message::Select(u) => {
                self.selected = Some(u);
                self.graph_cache.clear();
            }
            Message::Undo => self.act(Request::Undo),
            Message::Suppress(unit) => self.act(Request::Suppress { unit, until: Until::Explicit }),
            Message::Unsuppress(unit) => self.act(Request::Unsuppress { unit }),
        }
        Task::none()
    }

    /// §16a: start visible only when something needs attention.
    fn needs_attention(&self) -> bool {
        let Some(r) = &self.report else { return true };
        let s = &r.status;
        s.incidents.iter().any(|i| i.state != IncidentState::Closed)
            || !s.pending.is_empty()
            || !s.interlock.is_empty()
            || s.reconciliation.as_ref().is_some_and(|a| !a.is_empty())
            || r.last_change_reverted
    }

    fn view(&self) -> Element<'_, Message> {
        let tab = |label: &'static str, v: View| {
            let b = button(text(label)).on_press(Message::Show(v));
            if self.view == v { b.style(button::primary) } else { b.style(button::secondary) }
        };
        let header = row![
            self.mark(28.0, Motion::Still),
            text("planarian").size(20),
            iced::widget::space::horizontal().width(12),
            tab("Graph", View::Graph),
            tab("Timeline", View::Timeline),
            tab("Generations", View::Generations),
            tab("Incidents", View::Incidents),
            iced::widget::space::horizontal(),
            button(text("Undo last change")).on_press(Message::Undo).style(button::secondary),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);
        let mut page = column![header].spacing(10).padding(12);
        if let Some((motion, what)) = self.activity() {
            page = page.push(
                container(
                    row![self.mark(40.0, motion), text(what).size(14)].spacing(12).align_y(iced::Alignment::Center),
                )
                .padding(6)
                .width(Fill)
                .style(container::rounded_box),
            );
        }
        if let Some(e) = &self.error {
            page = page.push(banner(e.clone(), true));
        }
        if let Some(r) = &self.report {
            for b in banners(r) {
                page = page.push(b);
            }
        }
        if let Some(a) = &self.answer {
            page = page.push(text(a.clone()).size(14));
        }
        page = page.push(rule::horizontal(1));
        let body: Element<'_, Message> = match (&self.report, self.view) {
            (None, _) => text("").into(),
            (Some(r), View::Graph) => self.graph_view(r),
            (Some(r), View::Timeline) => timeline(r),
            (Some(r), View::Generations) => generations(r),
            (Some(r), View::Incidents) => incidents(r),
        };
        page.push(body).into()
    }

    fn graph_view<'a>(&'a self, r: &'a ConsoleReport) -> Element<'a, Message> {
        let canvas = canvas(graph::Graph { report: r, selected: self.selected.as_ref(), cache: &self.graph_cache })
            .width(Fill)
            .height(Fill);
        let side: Element<'_, Message> =
            match self.selected.as_ref().and_then(|u| r.nodes.iter().find(|n| &n.unit == u)) {
                None => column![text("Select a unit.").size(14), text(graph::LEGEND).size(12),].spacing(8).into(),
                Some(n) => {
                    let action = if n.suppressed {
                        button(text("Let it run again")).on_press(Message::Unsuppress(n.unit.clone()))
                    } else {
                        button(text("Leave it alone")).on_press(Message::Suppress(n.unit.clone()))
                    };
                    column![
                        text(n.unit.to_string()).size(16),
                        text(format!("desired: {}{}", n.desired, if n.expected { "" } else { " (not now)" })).size(14),
                        text(format!("observed: {}", n.observed)).size(14),
                        text(format!("health: {}", status_words(&n.health))).size(14),
                        action,
                        text(graph::LEGEND).size(12),
                    ]
                    .spacing(8)
                    .into()
                }
            };
        row![canvas, container(side).width(280)].spacing(12).into()
    }
}

fn banner<'a>(s: String, warn: bool) -> Element<'a, Message> {
    container(text(s).size(14))
        .padding(8)
        .width(Fill)
        .style(if warn { container::danger } else { container::rounded_box })
        .into()
}

fn banners<'a>(r: &ConsoleReport) -> Vec<Element<'a, Message>> {
    let s = &r.status;
    let mut out = vec![];
    for (t, why) in &s.interlock {
        out.push(banner(
            format!(
                "Recovery failed (transaction {}): {why}. Automatic repair is stopped until an administrator runs `planarian resolve {}`.",
                t.0, t.0
            ),
            true,
        ));
    }
    for p in &s.pending {
        out.push(banner(format!("Waiting for approval: {} (as root: planarian approve {})", p.what, p.approve), false));
    }
    if let Some(n) = &s.baseline_note {
        out.push(banner(n.clone(), false));
    }
    if r.last_change_reverted {
        out.push(banner("The last configuration change was reverted; see the Timeline.".into(), false));
    }
    if let Some(sp) = &s.space
        && let Some(short) = sp.shortfall
    {
        out.push(banner(
            format!(
                "Generations are {:.1} GB over their space budget; Planarian cannot collect the ones it must keep, so the budget is a target, not a guarantee.",
                short as f64 / 1e9
            ),
            false,
        ));
    }
    if let Some(rec) = &s.reconciliation
        && !rec.is_empty()
    {
        out.push(banner(format!("After the last restart: {}", rec.join("; ")), false));
    }
    out
}

fn timeline<'a>(r: &'a ConsoleReport) -> Element<'a, Message> {
    let mut list = column![].spacing(6);
    if r.timeline.is_empty() {
        list = list.push(text("No transactions yet."));
    }
    for t in &r.timeline {
        let who = if t.by_watchdog { " · finished by the watchdog" } else { "" };
        let live = if t.live { " · in progress" } else { "" };
        let why = if t.why.is_empty() { String::new() } else { format!("\n    because {}", t.why) };
        list = list.push(
            text(format!(
                "#{}  {} — {}{live}{who}\n    {}{why}",
                t.txn.0,
                t.what,
                planarian_state_name(&t.state),
                t.path.join(" → ")
            ))
            .size(14),
        );
    }
    scrollable(list).height(Fill).into()
}

fn planarian_state_name(s: &planarian_schema::TxnState) -> String {
    match s {
        planarian_schema::TxnState::Rejected(r) => format!("Rejected ({r:?})"),
        planarian_schema::TxnState::Cancelled(a) => format!("Cancelled by {a:?}"),
        other => format!("{other:?}"),
    }
}

fn generations<'a>(r: &'a ConsoleReport) -> Element<'a, Message> {
    let s = &r.status;
    let g = |o: Option<planarian_schema::GenerationId>| o.map(|g| g.0.to_string()).unwrap_or_else(|| "—".into());
    let confirmed = |o: Option<planarian_schema::GenerationId>| {
        if o.is_some() && o == r.last_booted { " (boot-confirmed: running since boot)" } else { "" }
    };
    let mut rows = column![
        text(format!("current: {}{}", s.generation.0, confirmed(Some(s.generation)))).size(15),
        text(format!("previous: {}", g(r.previous))).size(15),
        text(format!(
            "known good: {}{}",
            g(s.known_good),
            if s.known_good.is_some() { " (boot-confirmed)" } else { "" }
        ))
        .size(15),
        text(format!("live-tested, not yet rebooted: {}", g(s.live_tested))).size(15),
        text(format!("accepted baseline: {}", g(s.accepted_baseline))).size(15),
        text(format!("boots by default: {}", g(s.boot_default))).size(15),
        text(format!("last booted: {}", g(r.last_booted))).size(15),
    ]
    .spacing(6);
    for c in &r.candidates {
        rows = rows.push(text(format!("candidate in progress: {}", c.0)).size(15));
    }
    if let Some(sp) = &s.space {
        rows = rows.push(
            text(format!(
                "space: {} generation(s), {:.1} GB of a {:.1} GB budget",
                sp.generations,
                sp.bytes as f64 / 1e9,
                sp.max_bytes as f64 / 1e9
            ))
            .size(15),
        );
    }
    rows.into()
}

fn incidents<'a>(r: &'a ConsoleReport) -> Element<'a, Message> {
    let mut list = column![].spacing(6);
    if r.status.incidents.is_empty() {
        list = list.push(text("No open incidents."));
    }
    for i in &r.status.incidents {
        let state = match &i.state {
            IncidentState::Cooldown { until } => format!("cooling down for {}", minutes(until.0, r.now.0)),
            IncidentState::Escalated { until } => {
                format!("needs a person (no automatic action for {})", minutes(until.0, r.now.0))
            }
            IncidentState::Open => "open".into(),
            s => format!("{s:?}").to_lowercase(),
        };
        list = list.push(
            text(format!(
                "#{}  {} — {}\n    {state}; {} attempt(s)",
                i.id.0,
                i.target,
                status_words(&i.divergence.1),
                i.attempts.len()
            ))
            .size(14),
        );
    }
    scrollable(list).height(Fill).into()
}

fn describe(r: &Response) -> String {
    match r {
        Response::Done { txn, state, message } => format!("transaction {}: {state:?}. {message}", txn.0),
        Response::NeedsApproval { what, approve, .. } => {
            format!("{what} needs approval (as root: planarian approve {approve})")
        }
        Response::Rejected { reason, message } => format!("refused ({reason}): {message}"),
        Response::Ok { message } | Response::Error { message } | Response::Unmatched { message } => message.clone(),
        other => format!("{other:?}"),
    }
}

/// A unit status in words.
pub fn status_words(s: &planarian_schema::UnitStatus) -> String {
    use planarian_schema::{Reason, UnitStatus as S};
    match s {
        S::Running => "running".into(),
        S::Degraded(probes) => {
            let names: Vec<&str> = probes.iter().map(|p| p.0.as_str()).collect();
            format!("running, but failing its health check ({})", names.join(", "))
        }
        S::Stopped => "stopped".into(),
        S::Suppressed => "left alone on request".into(),
        S::Unknown => "unknown (no fresh evidence)".into(),
        S::Failed(Reason::ExitCode(c)) => format!("failed (exit code {c})"),
        S::Failed(Reason::DriverError(e)) => format!("failed (driver: {e})"),
        S::Failed(Reason::Backend(e)) => format!("failed ({e})"),
        S::Absent => "absent".into(),
        S::Detected => "detected, no driver bound".into(),
        S::Bound => "bound to its driver".into(),
        S::Transitioning => "starting or stopping".into(),
        S::NotExpected => "not expected now".into(),
    }
}

/// "12 min", "1 h 5 min": from `now` until `until`, both in milliseconds.
fn minutes(until: u64, now: u64) -> String {
    let m = until.saturating_sub(now).div_ceil(60_000);
    if m >= 60 { format!("{} h {} min", m / 60, m % 60) } else { format!("{m} min") }
}
