# The invisibility budget (SPEC §21; catalog quiet-reference-workload; owner
# decision Q7). Two parts, one report (report.json in the output):
#
#   idle   planariad and planarian-recovery after settling: CPU (% of one
#          core), resident memory, and wakeups per second (context switches
#          of all their threads), over five minutes. Targets: CPU < 0.5%,
#          resident < 50 MB; wakeups reported.
#   game   Xonotic's timedemo under MangoHud, software-rendered (llvmpipe),
#          five runs per condition, interleaved: Planarian stopped, idle, and
#          busy (a watched service crashed and repaired every 30 s). Each
#          run's p99 frame time is compared between conditions with a
#          two-sided Mann-Whitney U test (alpha 0.01; with five runs a side,
#          only a complete separation is significant).
#
# Without a GPU this measures Planarian's CPU interference with a CPU-bound
# renderer, which is the harder case for it; a real reference machine runs
# the same script at phase gates. Run with:
#   nix build -L .#legacyPackages.x86_64-linux.bench.invisibility
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "planarian-invisibility";
  # The report is a free-form dict; the driver's type checker cannot follow it.
  skipTypeCheck = true;
  # Idle (7 min) plus fifteen game runs of up to 15 min each.
  globalTimeout = 16200;

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    services.planarian.healthReport.interval = 3600;
    virtualisation.cores = 4;
    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;
    environment.systemPackages = [ pkgs.xonotic pkgs.mangohud pkgs.xvfb-run pkgs.unzip pkgs.mesa-demos ];
    hardware.graphics.enable = true;

    # A watched service the busy condition crashes (repaired each time).
    systemd.services.bench-svc = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
    services.planarian.units.bench-svc = { };
  };

  testScript = ''
    import base64, itertools, json, re, statistics

    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("bench-svc.service")
    machine.succeed("mkdir -p /tmp/bench")
    report: dict = {}

    def pids():
        return [int(machine.succeed(f"systemctl show -p MainPID --value {u}").strip()) for u in ("planariad", "planarian-recovery")]

    def sample(pid):
        stat = machine.succeed(f"cat /proc/{pid}/stat").split(")")[-1].split()
        ticks = int(stat[11]) + int(stat[12])
        rss = int(re.search(r"VmRSS:\s+(\d+)", machine.succeed(f"cat /proc/{pid}/status")).group(1))
        sw = sum(int(x) for x in machine.succeed(
            f"cat /proc/{pid}/task/*/status | sed -n 's/^\\(non\\)\\?voluntary_ctxt_switches:[[:space:]]*//p'").split())
        return ticks, rss, sw

    with subtest("idle"):
        machine.sleep(120)
        window = 300
        before = {p: sample(p) for p in pids()}
        machine.sleep(window)
        after = {p: sample(p) for p in pids()}
        hz = int(machine.succeed("getconf CLK_TCK").strip())
        cpu = sum(after[p][0] - before[p][0] for p in before) / hz / window * 100
        rss_mb = sum(after[p][1] for p in after) / 1024
        wakeups = sum(after[p][2] - before[p][2] for p in before) / window
        report["idle"] = {"cpu_percent_of_one_core": round(cpu, 3), "resident_mb": round(rss_mb, 1),
                          "wakeups_per_second": round(wakeups, 2), "window_s": window,
                          "targets": {"cpu_percent_of_one_core": 0.5, "resident_mb": 50}}
        print(json.dumps(report["idle"]))

    # The demo: the benchmark demo Xonotic ships, else the first one found.
    # nixpkgs' xonotic installs xonotic-sdl (and xonotic-glx in some builds);
    # its data is a separate store path in the closure.
    game = machine.succeed(
        "for b in xonotic-glx xonotic-sdl xonotic; do command -v $b && break; done").strip().splitlines()[0]
    demos = machine.succeed(
        "for p in $(nix-store -qR /run/current-system | grep -i xonotic); do"
        " find $p -name '*.pk3' 2>/dev/null; done | sort -u | while read f; do"
        " unzip -Z1 $f 2>/dev/null | grep -i '^demos/.*\\.dem$'; done | sort -u || true").split()
    demo = next((d for d in demos if "keybench" in d), demos[0] if demos else None)
    report["game"] = {"binary": game, "demos_found": demos, "demo": demo, "renderer": machine.succeed(
        "xvfb-run -a glxinfo -B 2>/dev/null | grep -i 'renderer string' || true").strip()}

    def stopped(on):
        if on:
            # Planarian stopped on purpose: hold the posture's Absent responses.
            machine.succeed("systemctl mask --runtime planarian-failed@absent.target")
            machine.succeed("systemctl stop planariad planarian-recovery")
        else:
            machine.succeed("systemctl start planarian-recovery planariad")
            machine.wait_for_unit("planarian-ready.target")
            machine.succeed("systemctl unmask --runtime planarian-failed@absent.target")

    def run(cond, i, limit=900):
        assert demo
        out = f"/tmp/mh/{cond}-{i}"
        machine.succeed(f"rm -rf {out}; mkdir -p {out}")
        busy = cond == "busy"
        if busy:
            machine.succeed("systemd-run --unit=bench-crasher ${pkgs.runtimeShell} -c "
                            "'while true; do ${pkgs.coreutils}/bin/sleep 30; ${pkgs.systemd}/bin/systemctl kill --signal=SIGSEGV bench-svc; done'")
        _, log = machine.execute(
            f"MANGOHUD_CONFIG=no_display,autostart_log=1,output_folder={out} "
            f"timeout -s INT {limit} xvfb-run -a -s '-screen 0 320x240x24' mangohud --dlsym {game} "
            f"-nosound -benchmark {demo.removesuffix('.dem')} +exec effects-low.cfg +vid_fullscreen 0 "
            f"+vid_width 320 +vid_height 240 2>&1 | tail -n 40")
        if busy:
            machine.execute("systemctl stop bench-crasher")
        csv = machine.succeed(f"cat {out}/*.csv 2>/dev/null || true")
        rows = [l.split(",") for l in csv.splitlines()]
        header = next((r for r in rows if "frametime" in r), None)
        times = []
        if header:
            k = header.index("frametime")
            for r in rows[rows.index(header) + 1:]:
                try:
                    times.append(float(r[k]))
                except (ValueError, IndexError):
                    pass
        times.sort()
        p99 = times[int(len(times) * 0.99) - 1] if len(times) >= 100 else None
        source = "mangohud"
        # MangoHud writes its CSV when logging stops; without one, DarkPlaces'
        # own benchmark summary: "N frames S seconds F fps, one-second fps
        # min/avg/max: a b c". The slowest one-second window stands in for
        # the p99 frame time (1000 / min fps).
        engine = re.search(r"(\d+) frames ([\d.]+) seconds ([\d.]+) fps, one-second fps min/avg/max: ([\d.]+)", log)
        if p99 is None and engine and float(engine.group(4)) > 0:
            p99 = 1000.0 / float(engine.group(4))
            source = "darkplaces one-second min"
        result = {"frames": len(times) or (int(engine.group(1)) if engine else 0), "p99_ms": p99, "source": source,
                  "engine": engine.group(0) if engine else None, "tail": log.splitlines()[-12:],
                  "mangohud_files": machine.succeed(f"ls -la {out}").splitlines()[1:]}
        print(f"{cond}-{i}:", json.dumps(result, indent=1))
        return result

    def mann_whitney_p(a, b):
        # Exact two-sided p of the U statistic, by enumerating every split.
        pooled = a + b
        def u(x, y):
            return sum(1.0 if i > j else 0.5 if i == j else 0.0 for i in x for j in y)
        observed = abs(u(a, b) - len(a) * len(b) / 2)
        n, hits = 0, 0
        for idx in itertools.combinations(range(len(pooled)), len(a)):
            xa = [pooled[i] for i in idx]
            xb = [pooled[i] for i in range(len(pooled)) if i not in idx]
            n += 1
            hits += abs(u(xa, xb) - len(a) * len(b) / 2) >= observed - 1e-9
        return hits / n

    print(json.dumps(report["game"], indent=1))
    if demo:
        # A short probe first, for the log: what the game prints and what
        # MangoHud writes in three minutes.
        with subtest("probe"):
            report["game"]["probe"] = run("probe", 0, limit=180)
    if demo:
        with subtest("game"):
            runs = {"stopped": [], "idle": [], "busy": []}
            for i in range(5):
                for cond in ("stopped", "idle", "busy"):
                    stopped(cond == "stopped")
                    runs[cond].append(run(cond, i))
                    if cond == "stopped":
                        stopped(False)
                # A first round without one frame-time sample will not get
                # better: stop, and say so, instead of spending hours.
                if i == 0 and all(runs[c][0]["p99_ms"] is None for c in runs):
                    report["game"]["error"] = "the first round recorded no frame times"
                    break
            report["game"]["runs"] = runs
            p99 = {c: [r["p99_ms"] for r in rs if r["p99_ms"] is not None] for c, rs in runs.items()}
            report["game"]["p99_ms_median"] = {c: statistics.median(v) if v else None for c, v in p99.items()}
            for c in ("idle", "busy"):
                if len(p99[c]) == 5 and len(p99["stopped"]) == 5:
                    report["game"][f"p_{c}_vs_stopped"] = mann_whitney_p(p99[c], p99["stopped"])
            print(json.dumps(report["game"], indent=1))
    elif "error" not in report["game"]:
        report["game"]["error"] = "no demo in the Xonotic data"

    encoded = base64.b64encode(json.dumps(report).encode()).decode()
    machine.succeed(f"echo {encoded} | base64 -d > /tmp/bench/report.json")
    machine.copy_from_machine("/tmp/bench/report.json", "")

    # The budget (a ratchet: failing it fails this test).
    idle = report["idle"]
    assert idle["cpu_percent_of_one_core"] < 0.5, f"idle CPU {idle['cpu_percent_of_one_core']}% of a core"
    assert idle["resident_mb"] < 50, f"resident {idle['resident_mb']} MB"
    assert demo and "error" not in report["game"], report["game"].get("error")
    for c in ("idle", "busy"):
        p = report["game"].get(f"p_{c}_vs_stopped")
        assert p is not None, f"{c}: not enough frame-time samples"
        assert p >= 0.01, f"{c} vs stopped: p99 frame time differs (p = {p})"
  '';
}
