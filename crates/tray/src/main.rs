//! `planarian-tray`: the status indicator. A StatusNotifierItem (the
//! freedesktop tray protocol COSMIC's panel shows) with the planarian mark:
//! no dot when all is well, blue-grey while a change is being built or
//! applied, amber when something needs a look, red when something needs a
//! person. Its tooltip says what; clicking it opens the console. Read-only,
//! like the console in Phase A: it asks the daemon for its console report
//! every few seconds and changes nothing.

mod icon;
mod state;

use ksni::blocking::TrayMethods;
use planarian_ipc::{ConsoleReport, Request, Response, SOCKET};
use state::{Level, Summary, classify};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const POLL: Duration = Duration::from_secs(5);

/// One request to the daemon, one answer.
fn report() -> Result<ConsoleReport, String> {
    let path = std::env::var("PLANARIAN_SOCKET").unwrap_or_else(|_| SOCKET.into());
    let mut s = UnixStream::connect(&path).map_err(|e| e.to_string())?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    s.write_all(Request::Console.encode().as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    match serde_json::from_str(&line).map_err(|e| format!("bad answer: {e}"))? {
        Response::Console(r) => Ok(*r),
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// The console next to this binary (both ship in one package), else on PATH.
fn console_command() -> PathBuf {
    if let Ok(p) = std::env::var("PLANARIAN_CONSOLE") {
        return p.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("planarian-console")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| "planarian-console".into())
}

fn open_console() {
    // `--show`: the console stays up even when nothing needs attention.
    if let Err(e) = std::process::Command::new(console_command()).arg("--show").spawn() {
        eprintln!("planarian-tray: cannot start the console: {e}");
    }
}

struct Tray {
    summary: Summary,
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "planarian".into()
    }

    fn title(&self) -> String {
        "planarian".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn status(&self) -> ksni::Status {
        match self.summary.level {
            Level::Ok | Level::Working => ksni::Status::Active,
            Level::Attention | Level::Fault => ksni::Status::NeedsAttention,
        }
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        icon::SIZES
            .iter()
            .filter_map(|s| icon::render(self.summary.level, *s))
            .map(|(w, h, data)| ksni::Icon { width: w as i32, height: h as i32, data })
            .collect()
    }

    fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icon_pixmap()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: format!("planarian: {}", self.summary.line),
            description: String::new(),
            icon_name: String::new(),
            icon_pixmap: vec![],
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        open_console();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem { label: self.summary.line.clone(), enabled: false, ..Default::default() }.into(),
            ksni::MenuItem::Separator,
            StandardItem { label: "Open console".into(), activate: Box::new(|_| open_console()), ..Default::default() }
                .into(),
            StandardItem { label: "Quit".into(), activate: Box::new(|_| std::process::exit(0)), ..Default::default() }
                .into(),
        ]
    }
}

fn poll() -> Summary {
    match report() {
        Ok(r) => classify(Ok(&r)),
        Err(e) => classify(Err(&e)),
    }
}

fn main() {
    let tray = Tray { summary: poll() };
    // The panel may come up after this service; register once it does.
    let handle = match tray.assume_sni_available(true).spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("planarian-tray: {e}");
            std::process::exit(1);
        }
    };
    let mut last = None;
    loop {
        let s = poll();
        if last.as_ref() != Some(&s) {
            eprintln!("planarian-tray: {:?}: {}", s.level, s.line);
            last = Some(s.clone());
            handle.update(|t: &mut Tray| t.summary = s);
        }
        if handle.is_closed() {
            break;
        }
        std::thread::sleep(POLL);
    }
}
