#!/usr/bin/env python3
"""Full configured native registry capacity canary with resource evidence."""
from pathlib import Path
import json, os, re, subprocess, tempfile, time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(tempfile.mkdtemp(prefix="capacity.", dir=ROOT / ".cross-review/implementation/phase6"))
RUN = f"pingap-native-capacity-{os.getpid()}-{time.time_ns()}"
IMAGE = os.environ.get("PINGAP_CAPACITY_RUNNER", "rust:1.98-alpine")
BINARY = ROOT / "target/musl/debug/examples/native_capacity"

def run(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check)

def services():
    return sorted(run("ps", "--format", "{{.ID}} {{.Names}} {{.Image}}").stdout.splitlines())

def process_rss_bytes(pid):
    """Read the candidate's process RSS from the host procfs."""
    if not pid:
        return None
    status = Path(f"/proc/{pid}/status")
    try:
        for line in status.read_text().splitlines():
            if line.startswith("VmRSS:"):
                value = line.split()[1]
                return int(value) * 1024
    except (FileNotFoundError, PermissionError, ValueError, IndexError):
        return None
    return None

before = services()
(OUT / "services-before.json").write_text(json.dumps(before))
try:
    if not BINARY.exists():
        builder = os.environ.get("PINGAP_CAPACITY_BUILDER", "pingap-native-plan-builder")
        compile_result = run(
            "exec",
            "-e", "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-e", "CARGO_TARGET_DIR=/workspace/target/musl",
            "-w", "/workspace",
            builder,
            "/usr/local/cargo/bin/cargo",
            "build",
            "-p", "pingap-behaviour",
            "--example", "native_capacity",
            "--features", "full",
        )
        (OUT / "compile.log").write_text(compile_result.stdout + compile_result.stderr)
    if not BINARY.exists():
        raise RuntimeError(f"capacity binary missing: {BINARY}")
    (OUT / "binary-size.txt").write_text(str(BINARY.stat().st_size))
    started = time.monotonic()
    run("run", "-d", "--name", RUN, "--label", f"pingap.canary={RUN}",
        "--network", "none", "--cpus", "2", "--memory", "1g",
        "-v", f"{ROOT}:/workspace:ro", IMAGE,
        "/workspace/target/musl/debug/examples/native_capacity")
    peak_process_rss = 0
    process_rss_samples = 0
    peak_cgroup_memory = 0
    peak_cpu = 0.0
    samples = []
    while True:
        state = run("inspect", RUN, "--format", "{{.State.Running}} {{.State.ExitCode}}", check=False).stdout.strip()
        if state.startswith("false "):
            break
        pid = run("inspect", RUN, "--format", "{{.State.Pid}}", check=False).stdout.strip()
        process_rss = process_rss_bytes(pid)
        if process_rss is not None:
            process_rss_samples += 1
            peak_process_rss = max(peak_process_rss, process_rss)
        stats = run("stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}", RUN, check=False).stdout.strip()
        if stats:
            samples.append(stats)
            cpu, memory = stats.split("|", 1)[:2]
            try:
                peak_cpu = max(peak_cpu, float(cpu.rstrip("%")))
            except ValueError:
                pass
            usage = memory.split("/")[0].strip()
            units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
            match = re.match(r"([0-9.]+)\s*(B|KiB|MiB|GiB)", usage)
            if match:
                peak_cgroup_memory = max(peak_cgroup_memory, int(float(match.group(1)) * units[match.group(2)]))
        if time.monotonic() - started > 900:
            run("kill", RUN, check=False)
            raise TimeoutError("native capacity exceeded 900 seconds")
        time.sleep(0.5)
    exit_code = int(run("wait", RUN).stdout.strip())
    logs = run("logs", RUN, check=False).stdout + run("logs", RUN, check=False).stderr
    (OUT / "capacity.log").write_text(logs)
    (OUT / "stats.txt").write_text(
        "\n".join(samples)
        + "\npeak_cpu_percent=" + str(peak_cpu)
        + "\npeak_process_rss_bytes=" + str(peak_process_rss)
        + "\npeak_cgroup_memory_bytes=" + str(peak_cgroup_memory)
    )
    state = json.loads(run("inspect", RUN, "--format", "{{json .State}}").stdout)
    (OUT / "state.json").write_text(json.dumps(state, indent=2))
    if exit_code != 0 or state.get("OOMKilled"):
        raise RuntimeError(f"capacity process failed exit={exit_code} oom={state.get('OOMKilled')}")
    if peak_process_rss <= 0:
        raise RuntimeError("missing candidate process VmRSS evidence")
    metrics = re.search(r"NATIVE_CAPACITY_METRICS .+", logs)
    if not metrics:
        raise RuntimeError("missing capacity metrics")
    (OUT / "metrics.txt").write_text(metrics.group(0) + "\n")
    if "NATIVE_CAPACITY_PASS" not in logs:
        raise RuntimeError("missing capacity pass marker")
    required = ("domains=256", "entries_per_domain=5000", "profiles=2", "saturated=512", "reloads=8", "expiry_reused=true")
    missing = [value for value in required if value not in metrics.group(0)]
    if missing:
        raise RuntimeError("capacity evidence missing: " + ", ".join(missing))
finally:
    if run("inspect", RUN, "--format", '{{index .Config.Labels "pingap.canary"}}', check=False).stdout.strip() == RUN:
        run("rm", "-f", RUN, check=False)

after = services()
(OUT / "services-after.json").write_text(json.dumps(after))
if after != before:
    raise RuntimeError("unrelated service inventory changed")
result = {
    "run": RUN,
    "image": IMAGE,
    "configured_domains": 256,
    "configured_entries_per_domain": 5000,
    "profiles": 2,
    "peak_rss_bytes": peak_process_rss,
    "peak_process_rss_bytes": peak_process_rss,
    "process_rss_samples": process_rss_samples,
    "process_rss_source": "host /proc/<container State.Pid>/status VmRSS",
    "peak_cgroup_memory_bytes": peak_cgroup_memory,
    "peak_cpu_percent": peak_cpu,
    "metrics": metrics.group(0),
    "services_unchanged": True,
    "oom": False,
}
(OUT / "result.json").write_text(json.dumps(result, indent=2))
print("NATIVE_CAPACITY_PASS")
