//! `planarian` and `ask` (§16). One binary; invoked as `ask` (by name or as
//! `planarian ask`) it interprets a phrase.

use planarian_ipc::{Request, Response, SOCKET, StatusReport};
use planarian_schema::{
    ChangeId, Hash, IncidentState, OverrideDesired, Resolution, TxnId, UnitId, UnitStatus, Until, Value,
};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::net::UnixStream;

const USAGE: &str = "usage:
  planarian status [--json]
  planarian log [-n N]
  planarian incidents
  planarian ask \"<phrase>\"          (also: ask \"<phrase>\")
  planarian apply <change> [key=value ...]
  planarian stop <unit>               stop it and leave it stopped until the next boot
  planarian restart <unit>
  planarian override <unit> [--leave-alone|--stopped|--absent|--detached] [--until next-boot|explicit|<N>m]
  planarian release <unit>
  planarian gc
  planarian undo
  planarian diagnose <unit> [probe]
  planarian approve <hash>            root, at a terminal
  planarian cancel <txn>
  planarian resolve <txn> --as-committed|--as-reverted|--manual-repaired
  planarian mark-good [--accept-unconfirmed]
  planarian mark-security-floor       the running generation becomes the security floor

Units are written like `sshd`, `service:sshd`, `device:snd-hda0` or `service@1000:pipewire`.";

fn unit(s: &str) -> Result<UnitId, String> {
    if s.contains(':') {
        s.parse().map_err(|_| format!("not a unit: {s}"))
    } else {
        Ok(UnitId::service(s.trim_end_matches(".service")))
    }
}

fn value(s: &str) -> Value {
    match s {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => s.parse::<i64>().map(Value::Int).unwrap_or_else(|_| Value::Str(s.into())),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn parse(args: &[String]) -> Result<(Request, bool), String> {
    let json = args.iter().any(|a| a == "--json");
    let args: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
    let req = match args.as_slice() {
        ["status"] | [] => Request::Status,
        ["log"] => Request::Log { limit: 40 },
        ["log", "-n", n] => Request::Log { limit: n.parse().map_err(|_| "-n needs a number")? },
        ["incidents"] => Request::Incidents,
        ["ask", rest @ ..] if !rest.is_empty() => Request::Ask { phrase: rest.join(" "), choice: None },
        ["apply", change, kv @ ..] => {
            let mut a = BTreeMap::new();
            for p in kv {
                let (k, v) = p.split_once('=').ok_or_else(|| format!("expected key=value, got {p}"))?;
                a.insert(k.to_string(), value(v));
            }
            Request::Apply { change: ChangeId(change.to_string()), args: a }
        }
        ["stop", u] => Request::Stop { unit: unit(u)? },
        ["restart", u] => Request::Restart { unit: unit(u)? },
        ["override", u, flags @ ..] => {
            let mut until = Until::Explicit;
            let mut desired = OverrideDesired::LeaveAlone;
            let mut it = flags.iter();
            while let Some(f) = it.next() {
                match *f {
                    "--leave-alone" => desired = OverrideDesired::LeaveAlone,
                    "--stopped" | "--stop" => desired = OverrideDesired::Stopped,
                    "--absent" => desired = OverrideDesired::Absent,
                    "--detached" => desired = OverrideDesired::Detected,
                    "--until" => {
                        until = match it.next().copied() {
                            Some("next-boot") => Until::NextBoot,
                            Some("explicit") => Until::Explicit,
                            Some(m) => {
                                let mins: u64 = m
                                    .trim_end_matches('m')
                                    .parse()
                                    .map_err(|_| "--until takes next-boot, explicit or <N>m")?;
                                Until::At(planarian_schema::Timestamp(now_ms() + mins * 60_000))
                            }
                            None => return Err("--until takes next-boot, explicit or <N>m".into()),
                        }
                    }
                    other => return Err(format!("override: unknown flag {other}")),
                }
            }
            Request::SetOverride { unit: unit(u)?, until, desired }
        }
        ["release", u] => Request::LiftOverride { unit: unit(u)? },
        ["gc"] => Request::Gc,
        ["undo"] => Request::Undo,
        ["diagnose", u] => Request::Diagnose { unit: unit(u)?, probe: None },
        ["diagnose", u, p] => {
            Request::Diagnose { unit: unit(u)?, probe: Some(planarian_schema::ProbeId(p.to_string())) }
        }
        ["approve", h] => {
            if !std::io::stdin().is_terminal() {
                // The daemon decides (from the process, not from us); this
                // only says why it will refuse.
                eprintln!("note: approval needs an interactive terminal; this one has none");
            }
            Request::Approve { hash: Hash::from_hex(h).ok_or("approve takes the 64-character hash shown by status")? }
        }
        ["cancel", t] => Request::Cancel { txn: TxnId(t.parse().map_err(|_| "cancel takes a transaction number")?) },
        ["resolve", t, how] => Request::Resolve {
            txn: TxnId(t.parse().map_err(|_| "resolve takes a transaction number")?),
            resolution: match *how {
                "--as-committed" => Resolution::AsCommitted,
                "--as-reverted" => Resolution::AsReverted,
                "--manual-repaired" => Resolution::ManualRepaired,
                _ => return Err("resolve needs --as-committed, --as-reverted or --manual-repaired".into()),
            },
        },
        ["agent", "run", name, "--", argv @ ..] if !argv.is_empty() => {
            Request::AgentRun { name: name.to_string(), argv: argv.iter().map(|s| s.to_string()).collect() }
        }
        ["ack"] => Request::Acknowledge { unit: None },
        ["ack", u] => Request::Acknowledge { unit: Some(unit(u)?) },
        ["mark-security-floor"] => Request::MarkSecurityFloor,
        ["mark-good"] => Request::MarkGood { accept_unconfirmed: false },
        ["mark-good", "--accept-unconfirmed"] => Request::MarkGood { accept_unconfirmed: true },
        _ => return Err(USAGE.into()),
    };
    Ok((req, json))
}

fn send(req: &Request) -> Result<Response, String> {
    let path = std::env::var("PLANARIAN_SOCKET").unwrap_or_else(|_| SOCKET.into());
    let mut s = UnixStream::connect(&path).map_err(|e| format!("cannot reach planariad at {path}: {e}"))?;
    // Long work runs off the core thread; the slowest answer is a diagnosis
    // probe with a long timeout. Ten minutes without one means planariad is
    // stuck: say so rather than hang.
    s.set_read_timeout(Some(std::time::Duration::from_secs(600))).map_err(|e| e.to_string())?;
    s.write_all(req.encode().as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("bad response: {e}"))
}

fn symbol(s: &UnitStatus, expected: bool) -> &'static str {
    match s {
        UnitStatus::Running => "ok",
        _ if !expected => "  ",
        UnitStatus::Overridden(_) => "--",
        UnitStatus::Unknown | UnitStatus::Transitioning => "??",
        UnitStatus::Bound => "ok",
        _ => "!!",
    }
}

fn print_status(r: &StatusReport) {
    println!(
        "generation {}   known-good {}   boot default {}",
        r.generation.0,
        r.known_good.map(|g| g.0.to_string()).unwrap_or("-".into()),
        r.boot_default.map(|g| g.0.to_string()).unwrap_or("-".into())
    );
    if let Some(n) = &r.baseline_note {
        println!("note: {n}");
    }
    for (t, why) in &r.interlock {
        println!(
            "\nRECOVERY FAILED (transaction {}): {why}\n  autonomous repair is stopped; after fixing it: planarian resolve {} --manual-repaired",
            t.0, t.0
        );
    }
    println!();
    for u in &r.units {
        let st = if u.expected || matches!(u.status, UnitStatus::Overridden(_)) {
            format!("{:?}", u.status)
        } else {
            "not expected now".into()
        };
        println!("  {} {:<36} {}", symbol(&u.status, u.expected), u.unit.to_string(), st);
    }
    if !r.incidents.is_empty() {
        println!("\nincidents:");
        for i in &r.incidents {
            let state = match &i.state {
                IncidentState::Cooldown { .. } => "cooling down".to_string(),
                IncidentState::Escalated { .. } => "needs a person".to_string(),
                s => format!("{s:?}"),
            };
            println!("  #{} {} — {:?}, {} attempt(s), {state}", i.id.0, i.target, i.divergence.1, i.attempts.len());
        }
    }
    if !r.pending.is_empty() {
        println!("\nwaiting for approval (as root: planarian approve <hash>):");
        for p in &r.pending {
            println!("  transaction {}: {}\n    {}", p.txn.0, p.what, p.approve);
        }
    }
    for (t, s, what) in &r.in_flight {
        match planarian_ipc::waiting_words(s) {
            Some(w) => println!("\n{w}: transaction {}: {what}", t.0),
            None => println!("\nin progress: transaction {} ({s:?}): {what}", t.0),
        }
    }
    if let Some(sp) = &r.space {
        let gb = |n: u64| n as f64 / 1e9;
        println!(
            "\nspace: {} generation(s), {:.1} GB of a {:.1} GB budget (last collection removed {})",
            sp.generations,
            gb(sp.bytes),
            gb(sp.max_bytes),
            sp.collected
        );
        if let Some(short) = sp.shortfall {
            println!(
                "  over budget by {:.1} GB: the generations Planarian must keep are larger than the budget, so it is a target, not a guarantee",
                gb(short)
            );
        }
    }
    if let Some(rec) = &r.reconciliation
        && !rec.is_empty()
    {
        println!("\nafter the last restart:");
        for a in rec {
            println!("  {a}");
        }
    }
    if !r.inferred.is_empty() {
        println!("\ntaken as intended (stopped outside Planarian; `planarian ack` once seen):");
        for (u, why) in &r.inferred {
            println!("  {u}: {why}");
        }
    }
    if !r.notices.is_empty() {
        println!("\nrecent:");
        for n in r.notices.iter().rev().take(8).rev() {
            println!("  {n}");
        }
    }
}

/// Print a response; returns the exit code.
fn print(resp: &Response, json: bool) -> i32 {
    if json {
        println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
        return 0;
    }
    match resp {
        Response::Status(r) => print_status(r),
        Response::Console(r) => print_status(&r.status),
        Response::Log { lines } => {
            for l in lines {
                println!("{:>6}  {}", l.seq, l.text);
            }
        }
        Response::Incidents { incidents } if incidents.is_empty() => println!("no incidents"),
        Response::Incidents { incidents } => {
            for i in incidents {
                println!(
                    "#{} {} {:?} {:?} attempts={} budget={}",
                    i.id.0,
                    i.target,
                    i.divergence.1,
                    i.state,
                    i.attempts.len(),
                    i.budget_left
                );
            }
        }
        Response::Done { txn, message, .. } => println!("transaction {}: {message}", txn.0),
        Response::NeedsApproval { txn, approve, why, .. } => {
            println!(
                "transaction {} needs approval because {why}.\nTo approve, as root at a terminal:\n  planarian approve {approve}",
                txn.0
            )
        }
        Response::Rejected { reason, message } => {
            eprintln!("refused ({reason}): {message}");
            return 1;
        }
        Response::Confirm { choices } => {
            println!("Did you mean:");
            for c in choices {
                println!("  {}. {}", c.index + 1, c.understood);
            }
        }
        Response::Unmatched { message } => {
            println!("{message}");
            return 1;
        }
        Response::Ok { message } => println!("{message}"),
        Response::Error { message } => {
            eprintln!("error: {message}");
            return 1;
        }
    }
    0
}

fn run(args: Vec<String>) -> i32 {
    let (req, json) = match parse(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let resp = match send(&req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return 69;
        }
    };
    // `ask` with two candidates: let the user pick at a terminal.
    if let (Response::Confirm { choices }, Request::Ask { phrase, .. }) = (&resp, &req) {
        print(&resp, false);
        if !std::io::stdin().is_terminal() {
            return 1;
        }
        print!("Choose 1–{} (anything else cancels): ", choices.len());
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let Ok(n) = line.trim().parse::<usize>() else { return 1 };
        if n == 0 || n > choices.len() {
            return 1;
        }
        return match send(&Request::Ask { phrase: phrase.clone(), choice: Some(n - 1) }) {
            Ok(r) => print(&r, json),
            Err(e) => {
                eprintln!("{e}");
                69
            }
        };
    }
    print(&resp, json)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = args.remove(0);
    let invoked_as_ask = std::path::Path::new(&argv0).file_name().is_some_and(|n| n == "ask");
    if args.first().is_some_and(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return;
    }
    if invoked_as_ask {
        args.insert(0, "ask".into());
    }
    std::process::exit(run(args));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Request {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>()).unwrap().0
    }

    #[test]
    fn parses_commands() {
        assert_eq!(p("status"), Request::Status);
        assert_eq!(p("stop sshd"), Request::Stop { unit: UnitId::service("sshd") });
        assert_eq!(
            p("release service@1000:pipewire"),
            Request::LiftOverride { unit: "service@1000:pipewire".parse().unwrap() }
        );
        assert_eq!(p("ask reconnect wifi"), Request::Ask { phrase: "reconnect wifi".into(), choice: None });
        match p("apply font-scale scale=1.25") {
            Request::Apply { change, args } => {
                assert_eq!(change.0, "font-scale");
                assert_eq!(args["scale"], Value::Str("1.25".into()));
            }
            r => panic!("{r:?}"),
        }
        assert!(matches!(
            p("resolve 4 --manual-repaired"),
            Request::Resolve { resolution: Resolution::ManualRepaired, .. }
        ));
        assert!(matches!(p("override backup --until 20m"), Request::SetOverride { until: Until::At(_), .. }));
        assert!(parse(&["bogus".into()]).is_err());
    }
}
