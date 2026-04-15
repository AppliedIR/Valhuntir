"""Setup command for Valhuntir — routes to subcommands.

Subcommands:
- vhir setup client   — Configure LLM client
- vhir setup test     — Test connectivity
- vhir setup join-code — Generate join code
"""

from __future__ import annotations

import sys
from pathlib import Path


def cmd_setup(args, identity: dict) -> None:
    """Run interactive setup or connectivity test."""
    action = getattr(args, "setup_action", None)

    if action == "test":
        _run_connectivity_test()
        return

    if action == "client":
        from vhir_cli.commands.client_setup import cmd_setup_client

        cmd_setup_client(args, identity)
        return

    if action == "join-code":
        from vhir_cli.commands.join import cmd_setup_join_code

        cmd_setup_join_code(args, identity)
        return

    # No subcommand — redirect to 'vhir setup client'
    print(
        "Usage: vhir setup <client|test|join-code>\n"
        "Run 'vhir setup client' to configure your LLM client.",
        file=sys.stderr,
    )
    sys.exit(1)


def _run_connectivity_test() -> None:
    """Test connectivity to the gateway and all MCP backends."""
    import json
    import re
    import shutil
    import subprocess
    import time
    import urllib.error
    import urllib.request

    print("=" * 60)
    print("  Valhuntir Connectivity Test")
    print("=" * 60)

    # --- Sandbox health check ---
    print("\n  Sandbox:")
    bwrap = shutil.which("bwrap")
    if not bwrap:
        print("    bwrap: NOT INSTALLED — kernel sandbox (L9) unavailable")
        print("    Install: sudo apt install bubblewrap")
    else:
        try:
            result = subprocess.run(
                [bwrap, "--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            result = None
            print("    bwrap: FAIL — test timed out (5s)")
            print("    bwrap may be hanging on a kernel call.")
            print("    Run: timeout 5 bwrap --ro-bind / / --unshare-net -- /bin/true")
        except Exception as e:
            result = None
            print(f"    bwrap: ERROR ({e})")

        if result is not None and result.returncode == 0:
            print("    bwrap: OK (network namespace works)")
        elif result is not None:
            bwrap_err = result.stderr.strip()

            # Diagnostic cascade — container detection
            is_container = False
            if shutil.which("systemd-detect-virt"):
                try:
                    r = subprocess.run(
                        ["systemd-detect-virt", "--container"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    is_container = r.returncode == 0 and r.stdout.strip() != "wsl"
                except Exception:
                    pass
            if not is_container:
                is_container = (
                    Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
                )
            if not is_container:
                try:
                    cgroup = Path("/proc/1/cgroup").read_text()
                    is_container = bool(
                        re.search(r"/(docker|lxc|containerd|kubepods)", cgroup)
                    )
                except Exception:
                    pass

            uname_r = ""
            try:
                uname_r = subprocess.run(
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout.strip()
            except Exception:
                pass

            is_wsl1 = (
                "Microsoft" in uname_r or "WSL" in uname_r
            ) and "microsoft-standard-WSL2" not in uname_r

            def _sysctl(name: str) -> str:
                try:
                    r = subprocess.run(
                        ["sysctl", "-n", name],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    return r.stdout.strip() if r.returncode == 0 else ""
                except Exception:
                    return ""

            if is_container:
                print("    bwrap: FAIL — running inside a container")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print("    Containers restrict namespace creation by default.")
                print("    Docker: --privileged or --security-opt seccomp=unconfined")
                print("    LXC/LXD: security.nesting=true")
            elif is_wsl1:
                print("    bwrap: FAIL — WSL1 does not support user namespaces")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print("    Upgrade to WSL2: wsl --set-version <distro> 2")
            elif _sysctl("kernel.apparmor_restrict_unprivileged_userns") == "1":
                print("    bwrap: FAIL — AppArmor blocks user namespaces")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print(
                    "    Fix: sudo apparmor_parser -rT /etc/apparmor.d/bwrap"
                    " (or reboot)"
                )
                print("    If no profile exists: re-run setup-sift.sh")
            elif _sysctl("kernel.unprivileged_userns_clone") == "0":
                print("    bwrap: FAIL — user namespaces disabled by sysctl")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print(
                    "    Temporary: sudo sysctl -w kernel.unprivileged_userns_clone=1"
                )
                print(
                    "    Permanent: echo"
                    " 'kernel.unprivileged_userns_clone=1' |"
                    " sudo tee /etc/sysctl.d/60-userns.conf"
                    " && sudo sysctl --system"
                )
            elif _sysctl("user.max_user_namespaces") == "0":
                print("    bwrap: FAIL — user namespace limit is zero")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print("    Fix: sudo sysctl -w user.max_user_namespaces=15000")
            else:
                print("    bwrap: FAIL — cannot create network namespace")
                if bwrap_err:
                    print(f"    bwrap stderr: {bwrap_err}")
                print("    Run: bwrap --ro-bind / / --unshare-net -- /bin/true")

    # --- Socat check (sandbox network proxy requires it) ---
    socat = shutil.which("socat")
    if bwrap and not socat:
        print("    socat: NOT INSTALLED — sandbox network proxy requires it")
        print("    Install: sudo apt install socat")
    elif bwrap and socat:
        print("    socat: OK")

    # Resolve gateway URL
    from vhir_cli.gateway import get_local_gateway_url, get_local_ssl_context

    gateway_url = get_local_gateway_url()
    ssl_ctx = get_local_ssl_context()

    health_url = f"{gateway_url}/health"
    print(f"\n  Gateway: {gateway_url}")

    # Fetch health with retries for startup delay (~6s typical)
    data = None
    urlopen_kwargs = {"timeout": 15}
    if ssl_ctx is not None:
        urlopen_kwargs["context"] = ssl_ctx
    # Poll every 2s for up to 60s — backends need time to start (triage DB ~37s)
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            req = urllib.request.Request(health_url)
            start = time.time()
            with urllib.request.urlopen(req, **urlopen_kwargs) as resp:
                elapsed = (time.time() - start) * 1000
                data = json.loads(resp.read())
            break
        except urllib.error.URLError:
            if attempt < max_attempts - 1:
                if attempt == 0:
                    print("  Gateway starting up, waiting...")
                if attempt == 15:
                    print("  Still waiting for gateway (loading databases)...")
                time.sleep(2)
            else:
                print("  Gateway: OFFLINE — is the gateway running?")
                print("    Start with: vhir service start")
                return
        except Exception as e:
            print(f"  Gateway: ERROR ({e})")
            return

    status = data.get("status", "unknown")
    tools_count = data.get("tools_count", 0)
    print(f"  Status: {status} ({tools_count} tools, {elapsed:.0f}ms)")

    backends = data.get("backends", {})
    if not backends:
        print("\n  No backends configured.")
        return

    ok_count = 0
    fail_count = 0

    print()
    for name, health in sorted(backends.items()):
        bstatus = health.get("status", "unknown")
        if bstatus == "ok":
            tools = health.get("tools", "?")
            print(f"  {name:25s} OK ({tools} tools)")
            ok_count += 1
        else:
            err = health.get("error", "unknown error")
            print(f"  {name:25s} FAIL ({err})")
            fail_count += 1

    print(f"\n{ok_count} of {ok_count + fail_count} backends operational.", end="")
    if fail_count:
        print(f" {fail_count} failed.")
    else:
        print()
