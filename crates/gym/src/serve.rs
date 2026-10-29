//! `planarian-gym serve`: the daemon core over the fake machine, answering
//! the real socket protocol, with a short history worth looking at. For
//! trying the console (and the CLI) without a NixOS machine, and for
//! checking that the console draws what the daemon reports.

use crate::sim::{Sim, peer, unit};
use planarian_ipc::{Request, Response};
use planarian_schema::{ChangeId, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn apply(sim: &mut Sim, change: &str, args: &[(&str, &str)]) -> Response {
    let args = args.iter().map(|(k, v)| (k.to_string(), Value::Str(v.to_string()))).collect();
    sim.core.as_mut().expect("core").handle(peer("root"), Request::Apply { change: ChangeId(change.into()), args })
}

pub fn serve(socket: &str) {
    let mut sim = Sim::new();
    for _ in 0..3 {
        sim.tick();
    }
    // A change that commits, one that is reverted, a user's stop, a service
    // that keeps failing its health check, and one that is killed and repaired.
    for r in [
        apply(&mut sim, "font-scale", &[("scale", "1.25")]),
        apply(&mut sim, "listen-address", &[("service", "gym-web"), ("addr", "192.0.2.10")]),
    ] {
        eprintln!("{r:?}");
    }
    let core = sim.core.as_mut().expect("core");
    eprintln!("{:?}", core.handle(peer("root"), Request::Stop { unit: unit("gym-cache") }));
    sim.fake.w().blocked.insert(unit("gym-metrics"));
    sim.fake.w().signal(&unit("gym-db"), 11);
    for _ in 0..12 {
        sim.tick();
    }

    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).unwrap_or_else(|e| panic!("{socket}: {e}"));
    eprintln!("planarian-gym: serving the fake machine on {socket}");
    type Job = (Request, mpsc::Sender<Response>);
    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut line = String::new();
                if BufReader::new(&conn).read_line(&mut line).is_err() {
                    return;
                }
                let resp = match serde_json::from_str::<Request>(&line) {
                    Ok(req) => {
                        let (rtx, rrx) = mpsc::channel();
                        if tx.send((req, rtx)).is_err() {
                            return;
                        }
                        rrx.recv().unwrap_or(Response::Error { message: "stopped".into() })
                    }
                    Err(e) => Response::Error { message: format!("bad request: {e}") },
                };
                let _ = (&conn).write_all(resp.encode().as_bytes());
            });
        }
    });
    // One fake tick (5 s) per real second.
    let mut next = Instant::now();
    loop {
        match rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Ok((req, reply)) => {
                let resp = sim.core.as_mut().expect("core").handle(peer("root"), req);
                let _ = reply.send(resp);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                sim.tick();
                next = Instant::now() + Duration::from_secs(1);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}
