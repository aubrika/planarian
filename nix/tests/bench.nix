# Scoped headless evidence for SPEC §21, not personal-profile acceptance.
# Cumulative monitor-slice CPU includes owned transient and exited helpers. Real per-frame CSVs
# are required; minimum-FPS/periodic averages cannot stand in for p99.
# Input-to-display, scheduler wakeups, a real GPU/desktop and the approved
# reference workload remain separate reference-hardware measurements.
{ pkgs, self }:

let sourceRevision = self.rev or (self.dirtyRev or "unavailable"); in
pkgs.testers.runNixOSTest {
  name = "planarian-invisibility-headless";
  skipTypeCheck = true;
  globalTimeout = 16200;

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    services.planarian.healthReport.interval = 3600;
    virtualisation.cores = 4;
    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;
    environment.systemPackages = [
      pkgs.python3 pkgs.xonotic pkgs.mangohud pkgs.xvfb-run pkgs.unzip pkgs.mesa-demos
    ];
    environment.etc."planarian-bench/performance.py".source = ../gym/performance.py;
    hardware.graphics.enable = true;

    systemd.services.bench-svc = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
    services.planarian.units.bench-svc = { };
  };

  testScript = ''
    import base64, importlib.util, json, re, shlex, statistics

    spec = importlib.util.spec_from_file_location("performance", "${../gym/performance.py}")
    performance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(performance)
    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("bench-svc.service")
    machine.succeed("mkdir -p /tmp/bench/raw")
    report = {
        "format": 2,
        "source_revision": "${sourceRevision}",
        "scope": "headless complete owned monitor slice and software-rendered frame interference",
        "personal_profile_acceptance": "NOT_RUN",
        "input_to_display": {"status": "NOT_RUN", "reason": "no physical display/HID/optical capture in this VM"},
        "excluded": ["model", "personal desktop/console/tray", "physical input-to-display", "scheduler wakeup tracing",
                     "indirect work in shared nix-daemon/systemd manager and user application cgroups", "interactive CLI clients"],
        "sampling": {"settle_seconds": 120, "idle_window_seconds": 300, "memory_interval_seconds": 1,
                     "game_repetitions_per_condition": 5, "order": "interleaved stopped/idle/busy",
                     "frame_stream": "MangoHud log_interval=0; frametime ms, elapsed ns; no outlier removal"},
        "proposed_frame_guard": performance.FRAME_MARGIN,
        "statistical_equivalence": "NOT_ESTABLISHED",
        "tool_versions": {"MangoHud": "${pkgs.mangohud.version}", "Xonotic": "${pkgs.xonotic.version}"},
    }

    def cgroup_sample(unit_args, duration, interval=1):
        return json.loads(machine.succeed(
            f"python3 /etc/planarian-bench/performance.py cgroup-window {unit_args} "
            f"--duration {duration} --interval {interval}"))

    def stopped(on):
        if on:
            machine.succeed("systemctl mask --runtime planarian-failed@absent.target")
            machine.succeed("systemctl stop planariad planarian-recovery")
        else:
            machine.succeed("systemctl start planarian-recovery planariad")
            machine.wait_for_unit("planarian-ready.target")
            machine.succeed("systemctl unmask --runtime planarian-failed@absent.target")

    def run_game(condition, repetition, game, demo):
        directory = f"/tmp/bench/raw/{condition}-{repetition}"
        machine.succeed(f"mkdir -p {directory}")
        if condition == "busy":
            machine.succeed("systemd-run --unit=bench-crasher ${pkgs.runtimeShell} -c "
                            "'while true; do ${pkgs.coreutils}/bin/sleep 30; "
                            "${pkgs.systemd}/bin/systemctl kill --signal=SIGSEGV bench-svc; done'")
        try:
            # Explicit per-frame logging. Missing/incomplete output is a failed
            # measurement, even if the engine prints a plausible FPS summary.
            command = (
                f"env MANGOHUD_CONFIG=no_display,autostart_log=1,log_interval=0,output_folder={directory} "
                f"timeout -s INT 900 xvfb-run -a -s '-screen 0 320x240x24' mangohud --dlsym {shlex.quote(game)} "
                f"-nosound -benchmark {shlex.quote(demo.removesuffix('.dem'))} +exec effects-low.cfg "
                f"+vid_fullscreen 0 +vid_width 320 +vid_height 240 > {directory}/engine.log 2>&1"
            )
            status, _ = machine.execute(command)
        finally:
            if condition == "busy":
                machine.execute("systemctl stop bench-crasher")
        log = machine.succeed(f"cat {directory}/engine.log")
        files = machine.succeed(f"find {directory} -maxdepth 1 -name '*.csv' -print").splitlines()
        result = {"exit_status": status, "raw_directory": directory, "csv_files": files,
                  "engine_tail": log.splitlines()[-20:],
                  "frame_scope": "all rendered frames in the identical Xonotic timedemo process including initialization"}
        if status != 0:
            result["error"] = "game command failed/timed out"
        elif len(files) != 1:
            result["error"] = "expected exactly one raw per-frame CSV"
        else:
            try:
                result.update(performance.completed_game_frames(machine.succeed(f"cat {shlex.quote(files[0])}"), log,
                                                                exit_status=status, log_interval_ms=0))
            except performance.EvidenceError as error:
                result["error"] = str(error)
        print(f"{condition}-{repetition}:", json.dumps(result))
        return result

    def benchmark():
        report["hardware"] = {
            "scope": "guest-visible QEMU hardware; host/reference-laptop hardware is not established",
            "cpu": json.loads(machine.succeed("lscpu --json")),
            "memory": machine.succeed("cat /proc/meminfo"),
            "kernel": machine.succeed("uname -a").strip(),
            "renderer": machine.succeed("xvfb-run -a glxinfo -B").strip(),
        }
        report["tool_versions"].update({
            "systemd": machine.succeed("systemctl --version").splitlines()[0],
            "nix": machine.succeed("nix --version").strip(),
            "python": machine.succeed("python3 --version").strip(),
        })
        export = json.loads(machine.succeed("cat /etc/planarian/export.json"))
        canonical = json.loads(machine.succeed(
            "cat $(dirname $(dirname $(readlink -f $(command -v planariad))))/share/planarian/canonical.json"))
        definitions = export["units"]
        merged = []
        for definition in definitions:
            name = definition["id"].rsplit(":", 1)[-1]
            probes = {probe["id"]: probe for probe in definition["probes"]}
            probes.update({probe["id"]: probe for probe in canonical.get(name, [])})
            merged.extend(probes.values())
        status = json.loads(machine.succeed("planarian --json status"))
        report["configuration"] = {
            "declared_system_units": len(definitions), "declared_user_templates": len(export["userUnits"]),
            "observed_unit_instances": len(status["units"]),
            "merged_system_probe_definitions": len(merged),
            "readiness_probes": sum(probe["role"] == "Readiness" for probe in merged),
            "diagnostic_probes": sum(probe["role"] == "Diagnostic" for probe in merged),
            "exec_probes": sum(isinstance(probe["kind"], dict) and "Exec" in probe["kind"] for probe in merged),
            "system_unit_ids": [definition["id"] for definition in definitions],
            "counts_scope": "headless system units after canonical replacement; user templates are not active desktops",
        }
        monitor_root = machine.succeed("systemctl show --property=ControlGroup --value planarian-monitor.slice").strip()
        assert monitor_root, "persistent monitor accounting slice is absent"
        for unit in ("planariad.service", "planarian-recovery.service"):
            path = machine.succeed(f"systemctl show --property=ControlGroup --value {unit}").strip()
            assert path.startswith(monitor_root + "/"), f"{unit} escaped the measured accounting parent"
        report["owned_work_accounting"] = {
            "root": monitor_root,
            "services": ["planariad", "planarian-recovery", "planarian-respond@", "planarian-posture-check", "planarian-posture-lift"],
            "transient_paths": ["probe::sandbox_argv", "Nixos::activate_live_inner"],
            "ordinary_children": "fork/exec descendants inherit their service cgroup",
            "limits": "shared daemons and restarted applications retain their own cgroups; this is not attribution of all caused machine work",
        }

        with subtest("helper CPU is retained after the helper exits"):
            # The MainPID waits, then becomes sleep. Its short-lived yes child
            # consumes the CPU. cpu.stat must retain that child's work.
            machine.succeed("systemd-run --unit=bench-metric-fixture ${pkgs.runtimeShell} -c "
                            "'${pkgs.coreutils}/bin/timeout 3 ${pkgs.coreutils}/bin/yes > /dev/null; "
                            "${pkgs.coreutils}/bin/touch /run/bench-helper-ended; exec ${pkgs.coreutils}/bin/sleep infinity'")
            fixture = cgroup_sample("--unit bench-metric-fixture.service", 5, 0.1)
            machine.succeed("test -e /run/bench-helper-ended")
            report["helper_cpu_control"] = fixture
            assert fixture["cpu_percent_of_one_core"] > 5, "exited helper CPU was not detected"
            machine.succeed("systemctl stop bench-metric-fixture")

        with subtest("idle complete service cgroups"):
            machine.sleep(120)
            idle = cgroup_sample("--unit planarian-monitor.slice", 300)
            report["idle"] = idle
            print(json.dumps(idle))
            assert idle["cpu_percent_of_one_core"] < 0.5, "whole-cgroup idle CPU budget exceeded"
            assert idle["resident_sampled_peak_mb"] < 50, "all-process sampled resident budget exceeded"
            assert idle["charged_lifetime_peak_upper_bound_mb"] < 50, "conservative complete-cgroup memory bound exceeded"

        game = machine.succeed(
            "for b in xonotic-glx xonotic-sdl xonotic; do command -v $b && break; done").strip().splitlines()[0]
        demos = machine.succeed(
            "for p in $(nix-store -qR /run/current-system | grep -i xonotic); do"
            " find $p -name '*.pk3' 2>/dev/null; done | sort -u | while read f; do"
            " unzip -Z1 $f 2>/dev/null | grep -i '^demos/.*\\.dem$'; done | sort -u || true").split()
        demo = next((value for value in demos if "keybench" in value), demos[0] if demos else None)
        report["game"] = {"binary": game, "demo": demo, "demos_found": demos,
                          "resolution": "320x240", "effects": "effects-low.cfg", "sound": "disabled",
                          "role": "headless CPU interference smoke; not the reviewed personal Proton workload"}
        assert demo, "no scripted Xonotic demo in the closure"
        runs = {"stopped": [], "idle": [], "busy": []}
        report["game"]["runs"] = runs
        with subtest("five interleaved per-frame repetitions"):
            for repetition in range(5):
                for condition in ("stopped", "idle", "busy"):
                    stopped(condition == "stopped")
                    try:
                        result = run_game(condition, repetition, game, demo)
                        runs[condition].append(result)
                    finally:
                        if condition == "stopped":
                            stopped(False)
                    assert "error" not in result, result.get("error")
            report["game"]["p99_ms_median"] = {
                condition: statistics.median(run["p99_ms"] for run in values)
                for condition, values in runs.items()
            }
            comparisons = performance.paired_frame_guards(runs)
            report["game"]["paired_guards"] = comparisons
            for condition in ("idle", "busy"):
                assert comparisons["conditions"][condition]["within_guard"], f"{condition}: proposed practical p99 guard exceeded"
        report["headless_scope_result"] = "PASS"

    try:
        benchmark()
    except Exception as error:
        report["headless_scope_result"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        encoded = base64.b64encode(json.dumps(report, allow_nan=False).encode()).decode()
        machine.succeed(f"echo {encoded} | base64 -d > /tmp/bench/report.json")
        machine.succeed("tar -C /tmp/bench -czf /tmp/bench/raw.tar.gz raw")
        machine.copy_from_machine("/tmp/bench/report.json", "")
        machine.copy_from_machine("/tmp/bench/raw.tar.gz", "")
  '';
}
