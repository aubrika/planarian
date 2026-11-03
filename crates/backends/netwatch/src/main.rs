//! `planarian-netwatch [--export PATH] [--object PATH] [--dir PATH]`:
//! attach the probes, keep the footprints, write the files (crate docs).
//! Defaults: `/etc/planarian/export.json`, `<prefix>/share/planarian/
//! netwatch.bpf.o`, `/run/planarian/footprint`. `--snapshot` prints what
//! stands now; `--check-object` checks the
//! object has every program; `--attach-test` attaches, waits for one event
//! and exits.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let object = flag("--object").unwrap_or_else(planarian_backend_netwatch::loader::default_object);
    if args.iter().any(|a| a == "--snapshot") {
        let names = planarian_backend_netwatch::host::read_ifnames();
        match planarian_backend_netwatch::snapshot::standing(&mut |i| names.get(&i).cloned()) {
            Ok((cs, virt)) => {
                cs.iter().for_each(|c| {
                    println!(
                        "{:?} {} iface={} steers={}",
                        c.kind,
                        c.object,
                        c.iface.as_deref().unwrap_or("-"),
                        c.steers
                    )
                });
                println!("virtual links: {virt:?}");
            }
            Err(e) => {
                eprintln!("snapshot: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--check-object") {
        let r = std::fs::read(&object)
            .map_err(|e| format!("read {object}: {e}"))
            .and_then(|b| planarian_backend_netwatch::loader::check_object(&b));
        match r {
            Ok(()) => println!("{object}: all {} programs present", planarian_backend_netwatch::loader::PROBES.len()),
            Err(e) => {
                eprintln!("{object}: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--attach-test") {
        match planarian_backend_netwatch::loader::attach_test(std::path::Path::new(&object)) {
            Ok(msg) => println!("{msg}"),
            Err(e) => {
                eprintln!("attach failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let export = flag("--export").unwrap_or_else(|| "/etc/planarian/export.json".into());
    let dir = flag("--dir").unwrap_or_else(|| planarian_backend_netwatch::DIR.into());
    let p = std::path::Path::new;
    let notify = std::env::var_os("NOTIFY_SOCKET").map(std::path::PathBuf::from);
    if let Err(e) = planarian_backend_netwatch::loader::run(p(&export), p(&object), p(&dir), notify.as_deref()) {
        eprintln!("planarian-netwatch: {e}");
        std::process::exit(1);
    }
}
