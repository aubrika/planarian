//! `planarian-netwatch`: attach the probes, keep the footprints, write the
//! files (crate docs). `--attach-test` attaches, waits for one event and
//! exits: a check that the kernel accepts the object.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let object = flag("--object").unwrap_or_else(planarian_backend_netwatch::loader::default_object);
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
    eprintln!("usage: planarian-netwatch --attach-test [--object PATH]");
    std::process::exit(2);
}
