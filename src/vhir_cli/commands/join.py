"""vhir join — exchange a join code for gateway credentials from a remote machine."""

from __future__ import annotations

import getpass
import json
import os
import socket
import sys
from pathlib import Path

import yaml


def cmd_join(args, identity: dict) -> None:
    """Join a SIFT gateway from a remote machine."""
    sift_url = args.sift
    code = args.code

    # Normalize URL — default to HTTPS for security (join codes are credentials)
    auto_https = False
    if not sift_url.startswith("http"):
        sift_url = f"https://{sift_url}"
        auto_https = True
    # Add default port if not present
    parts = sift_url.split("//", 1)
    if len(parts) == 2 and ":" not in parts[1]:
        sift_url = f"{sift_url}:4508"

    # Detect if this is a wintools machine
    wintools_url = None
    wintools_token = None
    if getattr(args, "wintools", False):
        wintools_url, wintools_token = _get_wintools_credentials()

    # TLS verification: use CA cert if available, otherwise skip (self-signed)
    ca_cert = getattr(args, "ca_cert", None) or _find_ca_cert()
    verify = ca_cert if ca_cert else False

    if not verify and sift_url.startswith("https"):
        print(
            "WARNING: TLS certificate verification disabled. "
            "Connection is encrypted but server identity is not verified. "
            "Use --ca-cert to specify a CA certificate.",
            file=sys.stderr,
        )

    join_body = _join_body(code, wintools_url, wintools_token, args)

    # POST to /api/v1/setup/join
    try:
        import requests
    except ImportError:
        # Fall back to urllib if requests is not available
        _join_urllib(sift_url, join_body, verify, args)
        return

    try:
        resp = requests.post(
            f"{sift_url}/api/v1/setup/join",
            json=join_body,
            verify=verify,
            timeout=30,
        )
    except requests.exceptions.SSLError as e:
        print(f"TLS error: {e}", file=sys.stderr)
        if auto_https:
            print(
                "If the gateway uses plain HTTP, specify the URL explicitly: "
                f"http://{sift_url.split('://', 1)[1]}",
                file=sys.stderr,
            )
        else:
            print(
                "Try --ca-cert to specify the CA certificate, "
                "or check the gateway's TLS config.",
                file=sys.stderr,
            )
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        if auto_https:
            print(
                f"Verify that the gateway is running at {sift_url}. "
                "If the gateway uses plain HTTP, specify the URL explicitly: "
                f"http://{sift_url.split('://', 1)[1]}",
                file=sys.stderr,
            )
        else:
            print(
                f"Verify that the gateway is running at {sift_url}",
                file=sys.stderr,
            )
        sys.exit(1)

    if resp.status_code != 200:
        try:
            error_msg = resp.json().get("error", "Unknown error")
        except (json.JSONDecodeError, ValueError):
            error_msg = resp.text
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)

    _joined(resp.json(), args)


def _join_body(code, wintools_url, wintools_token, args) -> dict:
    body = {
        "code": code,
        "machine_type": "wintools" if wintools_url else "examiner",
        "hostname": socket.gethostname(),
        "wintools_url": wintools_url,
        "wintools_token": wintools_token,
    }
    if isinstance(getattr(args, "name", None), str):
        body["name"] = args.name
    return body


def _joined(data: dict, args) -> None:
    """Save the token and say what the join did: the name joined as, and the
    command that enrols that name for approvals."""
    if data.get("gateway_token"):
        _write_config(data["gateway_url"], data["gateway_token"])

    print(f"Joined gateway at {data['gateway_url']}")
    print(f"Backends available: {', '.join(data.get('backends', []))}")
    name = data.get("examiner")
    if data.get("gateway_token") and name:
        if data.get("bound"):
            print(f"Joined as {name}; your earlier token for {name} no longer works.")
        else:
            print(f"Joined as {name}.")
        print(
            "To approve in the Examiner Portal, the examiner named enrols once, at the "
            "SIFT terminal (if not already enrolled):"
        )
        print(f"  {data.get('enrol_command') or f'vhir enrol --name {name}'}")

    if data.get("wintools_registered"):
        print("Windows wintools-mcp registered with gateway")
        if data.get("restart_required"):
            print(
                "Note: gateway restart may be needed to activate the wintools backend"
            )

    # Run vhir setup client to generate MCP config
    if not getattr(args, "skip_setup", False):
        print()
        print("Run 'vhir setup client --remote' to configure your LLM client.")


def _code_body(args) -> dict:
    body = {"expires_hours": getattr(args, "expires", None) or 2}
    if isinstance(getattr(args, "name", None), str):
        body["name"] = args.name
    return body


def cmd_setup_join_code(args, identity: dict) -> None:
    """Generate a join code on this SIFT machine.

    If the gateway is bound to localhost, prompts to rebind to 0.0.0.0
    so remote machines can connect, then restarts the gateway.
    """
    token = _get_local_gateway_token()

    if not token:
        print("No gateway token found. Is the gateway configured?", file=sys.stderr)
        print("Check ~/.vhir/gateway.yaml for api_keys", file=sys.stderr)
        sys.exit(1)

    if getattr(args, "revoke", False) is True:
        _revoke_join_codes(_get_local_gateway_url(), token)
        return

    # Configure static IP before remote binding
    static_ip = _ensure_static_ip()

    # Check if gateway needs rebinding for remote access
    _ensure_remote_binding()

    gateway_url = _get_local_gateway_url()

    try:
        import requests
    except ImportError:
        data = _join_code_urllib(gateway_url, token, args)
        _post_join_code_setup(data, static_ip)
        return

    ca = _find_ca_cert()
    verify = ca if ca else False
    if not verify and gateway_url.startswith("https"):
        print(
            "WARNING: TLS certificate verification disabled for join-code request. "
            "Use ~/.vhir/tls/ca-cert.pem to enable verification.",
            file=sys.stderr,
        )
    try:
        resp = requests.post(
            f"{gateway_url}/api/v1/setup/join-code",
            headers={"Authorization": f"Bearer {token}"},
            json=_code_body(args),
            verify=verify,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Failed to connect to local gateway: {e}", file=sys.stderr)
        print(f"Is the gateway running at {gateway_url}?", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        try:
            why = resp.json().get("error", resp.text)
        except ValueError:
            why = resp.text
        print(f"Failed to generate join code: {why}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    _post_join_code_setup(data, static_ip)


def _join_urllib(sift_url, join_body, verify, args):
    """Fallback join implementation using urllib (no requests dependency)."""
    import ssl
    import urllib.request

    payload = json.dumps(join_body).encode("utf-8")

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx.load_verify_locations(verify)

    req = urllib.request.Request(
        f"{sift_url}/api/v1/setup/join",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            error_msg = json.loads(body).get("error", body)
        except (json.JSONDecodeError, ValueError):
            error_msg = body
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    _joined(data, args)


def _revoke_join_codes(gateway_url: str, token: str) -> None:
    """End every unused join code (DELETE /api/v1/setup/join-code)."""
    import ssl
    import urllib.request

    ca = _find_ca_cert()
    ctx = ssl.create_default_context()
    if not ca:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(ca)
    req = urllib.request.Request(
        f"{gateway_url}/api/v1/setup/join-code",
        method="DELETE",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            revoked = json.loads(resp.read()).get("revoked", 0)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"Failed to revoke join codes: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Ended {revoked} unused join code{'' if revoked == 1 else 's'}.")


def _join_code_urllib(gateway_url, token, args) -> dict:
    """Fallback join-code implementation using urllib. Returns response data."""
    import ssl
    import urllib.request

    payload = json.dumps(_code_body(args)).encode("utf-8")

    ca = _find_ca_cert()
    ctx = ssl.create_default_context()
    if not ca:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(ca)

    req = urllib.request.Request(
        f"{gateway_url}/api/v1/setup/join-code",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"Failed to generate join code: {e}", file=sys.stderr)
        sys.exit(1)


def _write_config(gateway_url: str, gateway_token: str) -> None:
    """Write gateway credentials to ~/.vhir/config.yaml.

    config.yaml's gateway_url is for remote clients only (written by 'vhir join'
    on a remote machine). Local SIFT commands read gateway.yaml instead.
    """
    from urllib.parse import urlparse

    # Validate URL to prevent malformed values (e.g. doubled scheme)
    parsed = urlparse(gateway_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print(
            f"Warning: invalid gateway URL '{gateway_url}', not saving to config",
            file=sys.stderr,
        )
        return

    config_dir = Path.home() / ".vhir"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = config_dir / "config.yaml"

    # Load existing config to preserve other fields
    config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError):
            pass

    config["gateway_url"] = gateway_url
    config["gateway_token"] = gateway_token

    fd = os.open(str(config_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def _get_local_gateway_url() -> str:
    """Build the local gateway URL from gateway.yaml config."""
    from vhir_cli.gateway import get_local_gateway_url

    return get_local_gateway_url()


def _get_local_gateway_token() -> str | None:
    """Get the first API key from the local gateway config."""
    # Try gateway.yaml first
    for config_name in ("gateway.yaml", "config.yaml"):
        config_path = Path.home() / ".vhir" / config_name
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
                # Check for api_keys dict
                api_keys = config.get("api_keys", {})
                if api_keys:
                    return next(iter(api_keys))
                # Check for gateway_token
                token = config.get("gateway_token")
                if token:
                    return token
            except (yaml.YAMLError, OSError):
                continue
    return None


def _get_wintools_credentials() -> tuple[str | None, str | None]:
    """Get wintools URL and token if available."""
    wintools_config = Path.home() / ".vhir" / "wintools.yaml"
    if wintools_config.exists():
        try:
            with open(wintools_config) as f:
                config = yaml.safe_load(f) or {}
            url = config.get("url", "http://127.0.0.1:4624/mcp")
            token = config.get("token")
            return url, token
        except (yaml.YAMLError, OSError):
            pass
    return None, None


TTY = "/dev/tty"


def _ask(question: str, no_terminal: str | None) -> str | None:
    """Ask a question on the terminal, even when stdout is captured.

    setup-sift.sh captures join-code's output, so a question printed to
    stdout is never seen: when stdout isn't a terminal, ask on /dev/tty.
    With no terminal to ask on, return ``no_terminal``, the safe answer
    (None for a question that has none).
    """
    if sys.stdout.isatty():
        return input(question)
    line = ""
    try:
        with open(TTY) as tty_in, open(TTY, "w") as tty_out:
            tty_out.write(question)
            tty_out.flush()
            line = tty_in.readline()
    except OSError:
        pass
    if line:
        return line.rstrip("\n")
    took = "no answer" if no_terminal is None else f"answered {no_terminal!r}"
    asked = question.strip().splitlines()[-1]
    print(f"No terminal to ask {asked!r}: {took}", file=sys.stderr)
    return no_terminal


def _ensure_remote_binding() -> None:
    """Check if gateway is localhost-only and offer to rebind for remote access.

    Only acts when gateway.host is exactly '127.0.0.1' and no TLS is configured.
    Prompts the user, updates gateway.yaml, and restarts the gateway service.
    """
    import subprocess
    import time

    gateway_config = Path.home() / ".vhir" / "gateway.yaml"
    if not gateway_config.exists():
        return

    try:
        with open(gateway_config) as f:
            config = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return

    gw = config.get("gateway", {})
    if not isinstance(gw, dict):
        return

    # Only rebind if bound to localhost; don't touch 0.0.0.0, custom IPs, or TLS
    if gw.get("host") != "127.0.0.1":
        return
    if gw.get("tls"):
        return

    print("The gateway is bound to 127.0.0.1 (localhost only).")
    print("Remote machines cannot connect until it binds to 0.0.0.0.")
    print()
    answer = input("Rebind gateway to 0.0.0.0 and restart? [Y/n] ").strip().lower()
    if answer in ("n", "no"):
        print(
            "Skipped. To rebind manually, edit ~/.vhir/gateway.yaml "
            "and restart the gateway.",
            file=sys.stderr,
        )
        return

    # Update gateway.yaml
    config["gateway"]["host"] = "0.0.0.0"
    try:
        fd = os.open(str(gateway_config), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            # Owner's key first: local readers take the first api_key.
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    except OSError as e:
        print(f"Failed to update gateway.yaml: {e}", file=sys.stderr)
        return

    # Restart gateway via systemd
    print("Restarting gateway...", end="", flush=True)
    try:
        result = subprocess.run(
            ["systemctl", "--user", "restart", "vhir-gateway"],
            timeout=15,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f" failed: {result.stderr.strip()}", file=sys.stderr)
            print(
                "Try manually: systemctl --user restart vhir-gateway",
                file=sys.stderr,
            )
            return
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f" failed: {e}", file=sys.stderr)
        return

    # Wait for gateway to become healthy
    from vhir_cli.gateway import (
        RECONNECT_HINT,
        get_local_gateway_url,
        get_local_ssl_context,
    )

    port = gw.get("port", 4508)
    health_url = f"{get_local_gateway_url()}/health"
    ssl_ctx = get_local_ssl_context()
    for _attempt in range(10):
        time.sleep(1)
        try:
            import urllib.request

            kwargs = {"timeout": 3}
            if ssl_ctx is not None:
                kwargs["context"] = ssl_ctx
            with urllib.request.urlopen(health_url, **kwargs) as resp:
                if resp.status == 200:
                    print(" done.")
                    print(f"Gateway now listening on 0.0.0.0:{port} (all interfaces).")
                    print(RECONNECT_HINT)
                    return
        except OSError:
            print(".", end="", flush=True)

    print(" gateway did not become healthy in time.", file=sys.stderr)
    print("Check: systemctl --user status vhir-gateway", file=sys.stderr)


def _find_ca_cert() -> str | None:
    """Find CA certificate for TLS verification."""
    from vhir_cli.gateway import find_ca_cert

    return find_ca_cert()


def derive_smb_password(join_code: str) -> str:
    """Derive SMB password from join code using PBKDF2-SHA256."""
    import hashlib

    dk = hashlib.pbkdf2_hmac("sha256", join_code.encode(), b"vhir-smb-v1", 600_000)
    return dk.hex()[:32]


def _get_sift_ip() -> str | None:
    """Read static IP from ~/.vhir/network.yaml."""
    p = Path.home() / ".vhir" / "network.yaml"
    if not p.is_file():
        return None
    try:
        doc = yaml.safe_load(p.read_text())
        return doc.get("static_ip")
    except Exception:
        return None


def _detect_ip() -> str:
    """Detect current IP via UDP socket trick."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _setup_firewall(wintools_ip: str) -> None:
    """Add UFW rules for gateway (4508) and SMB (445), restricted to wintools IP."""
    import shutil
    import subprocess

    if not shutil.which("ufw"):
        print("UFW not installed — skipping firewall rules.", file=sys.stderr)
        return

    # Check if UFW is active
    result = subprocess.run(
        ["sudo", "ufw", "status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:  # sudo refused, say: whether UFW is active is unknown
        raise RuntimeError(
            f"'sudo ufw status' failed (exit {result.returncode}): "
            f"{result.stderr.strip() or 'no output'}"
        )
    if "Status: active" not in result.stdout:
        print(
            "UFW is not active — skipping firewall rules. "
            "Enable with 'sudo ufw enable' if needed.",
            file=sys.stderr,
        )
        return

    for port, label in [("4508", "Valhuntir gateway"), ("445", "Valhuntir SMB")]:
        try:
            subprocess.run(
                [
                    "sudo",
                    "ufw",
                    "allow",
                    "from",
                    wintools_ip,
                    "to",
                    "any",
                    "port",
                    port,
                    "comment",
                    label,
                ],
                check=True,
                capture_output=True,
                timeout=15,
            )
        except subprocess.CalledProcessError:
            # Retry without comment (older UFW versions)
            subprocess.run(
                [
                    "sudo",
                    "ufw",
                    "allow",
                    "from",
                    wintools_ip,
                    "to",
                    "any",
                    "port",
                    port,
                ],
                check=True,
                capture_output=True,
                timeout=15,
            )

    subprocess.run(
        ["sudo", "ufw", "reload"],
        capture_output=True,
        timeout=15,
    )


def _set_smb_password(join_code: str) -> None:
    """Give vhir-smb this join code's password and push it to wintools-mcp."""
    import subprocess

    derived_password = derive_smb_password(join_code)
    try:
        subprocess.run(
            ["sudo", "smbpasswd", "-a", "-s", "vhir-smb"],
            input=f"{derived_password}\n{derived_password}\n".encode(),
            check=True,
            capture_output=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to set SMB password: {e}") from e

    # Push updated SMB credentials to wintools-mcp if configured
    _push_smb_credentials(derived_password)


def check_share_path(path: str) -> None:
    """Refuse a path that can't be written as one smb.conf value.

    A line break would start a new smb.conf line, written as root, and a
    trailing backslash would join the next line onto this one.
    """
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise ValueError(f"case path has a control character: {path!r}")
    if path.endswith("\\"):
        raise ValueError(f"case path ends with a backslash: {path!r}")


def _active_case_dir() -> Path | None:
    """The active case's directory, if the pointer names one with a CASE.yaml."""
    try:
        case_dir = Path((Path.home() / ".vhir" / "active_case").read_text().strip())
    except OSError:
        return None
    if case_dir.is_absolute() and (case_dir / "CASE.yaml").is_file():
        return case_dir
    return None


SHARE_NAME = (
    "vhir-cases"  # vhir's own section; SIFT's stock [cases] and [mnt] stay as shipped
)
SMB_CONF_PATH = "/etc/samba/smb.conf.d/vhir-cases.conf"


def private_primary_group(username: str) -> str:
    """The name of `username`'s primary group, which the share writes files
    with: only when no other account NSS returns can be in it. Raises
    RuntimeError when another can. The SIFT box is trusted, so accounts from
    non-local sources (sss, ldap, ...) needn't all be listable: only what NSS
    returns is checked."""
    import grp
    import pwd

    group = grp.getgrgid(pwd.getpwnam(username).pw_gid)
    others = set(group.gr_mem) | {
        p.pw_name for p in pwd.getpwall() if p.pw_gid == group.gr_gid
    }
    others.discard(username)
    if others:
        raise RuntimeError(
            f"{username}'s primary group {group.gr_name!r} isn't {username}'s alone "
            f"({', '.join(sorted(others))} can use it): case files the share writes "
            f"would be writable by them. Give {username} a primary group of its own, "
            "then join again."
        )
    return group.gr_name


def _share_conf(doc: dict, target: str) -> str:
    """The share's Samba section, under the name `samba.yaml` gives (a box
    joined before vhir had its own share name keeps its old section)."""
    name = doc.get("share_name") or "cases"
    username = doc.get("force_user") or getpass.getuser()
    if name != SHARE_NAME:
        return f"""[{name}]
    path = {target}
    valid users = vhir-smb
    read only = no
    create mask = 0644
    directory mask = 0755
    force user = {username}
    force group = sift
    browsable = no
    hosts allow = {doc.get("wintools_ip", "")}
"""
    return f"""[{name}]
    path = {target}
    valid users = vhir-smb
    read only = no
    create mask = 0664
    directory mask = 0775
    force user = {username}
    force group = {doc.get("force_group") or username}
    browsable = no
    hosts allow = {doc.get("wintools_ip", "")}
"""


CASE_MARKER = (
    ".vhir-share-case"  # at a case's root: its folder name, which wintools checks
)


def share_settings() -> dict:
    """`~/.vhir/samba.yaml`, or {} when the share isn't set up."""
    try:
        doc = yaml.safe_load((Path.home() / ".vhir" / "samba.yaml").read_text())
    except (OSError, yaml.YAMLError):
        return {}
    return doc if isinstance(doc, dict) else {}


def mark_case(case_dir: Path) -> str | None:
    """Write the case's share marker (0644, its folder name): wintools
    writes through the share only while the marker names the case it was
    told is active. Returns why it couldn't be written, or None."""
    import stat

    marker = Path(case_dir) / CASE_MARKER  # never through a link (O_NOFOLLOW)
    refused = (
        f"Share marker not written: {marker} is not a regular file inside the case."
    )
    # truncated only once it is known to be a regular file with one link, so
    # a hard link to another case file is never emptied
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(marker, flags, 0o644)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                return refused
            os.ftruncate(fd, 0)
            os.fchmod(fd, 0o644)
            os.write(fd, Path(case_dir).name.encode())
        finally:
            os.close(fd)
    except OSError as e:
        return f"Share marker not written: {marker}: {e.strerror or e}"
    return None


def share_needs_rejoin() -> bool:
    """A box joined before vhir had its own share name: wintools has to join
    again to reach the case through it."""
    samba_yaml = Path.home() / ".vhir" / "samba.yaml"
    try:
        doc = yaml.safe_load(samba_yaml.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return False
    return (
        isinstance(doc, dict)
        and bool(doc.get("share_name"))
        and (doc["share_name"] != SHARE_NAME)
    )


def _mark_case_for_kept_share() -> None:
    active = _active_case_dir()
    if active is not None:  # the kept share still points at it: mark it
        warning = mark_case(active)
        if warning:
            print(
                f"Warning: {warning}; wintools writes nothing to the case.",
                file=sys.stderr,
            )


def _setup_samba_share(join_code: str) -> str | None:
    """Set up Samba share with PBKDF2-derived credentials. Returns wintools IP.
    A blank Windows IP keeps a configured share's IP (a share under an old
    name still moves), and with none means no Windows machine: None, no share."""
    import subprocess

    # Idempotency: skip if already configured, but every join code still
    # sets the password Windows will derive from it
    samba_yaml = Path.home() / ".vhir" / "samba.yaml"
    keep_ip = reconfigure_ip = moved_ip = None
    if samba_yaml.is_file():
        try:
            doc = yaml.safe_load(samba_yaml.read_text()) or {}
            if doc.get("share_name") and doc.get("wintools_ip"):
                configured = f"Samba share already configured for {doc['wintools_ip']}"
                if doc["share_name"] != SHARE_NAME:
                    print(configured)
                    print(
                        f"The share moves from [{doc['share_name']}] to [{SHARE_NAME}]."
                    )
                    moved_ip = str(doc["wintools_ip"])
                else:
                    answer = _ask(f"{configured}\nReconfigure? [y/N] ", "n")
                    if answer.strip().lower() not in ("y", "yes"):
                        keep_ip = doc["wintools_ip"]
                    else:
                        reconfigure_ip = doc["wintools_ip"]
        except (yaml.YAMLError, OSError):
            pass
    if keep_ip:
        _set_smb_password(join_code)
        _mark_case_for_kept_share()
        return keep_ip
    username = getpass.getuser()
    group = private_primary_group(username)  # before anything is installed or changed

    try:
        subprocess.run(
            ["sudo", "apt-get", "install", "-y", "samba"],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to install samba: {e}") from e

    try:
        subprocess.run(
            ["sudo", "groupadd", "-f", "sift"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to create sift group: {e}") from e

    # Create vhir-smb user
    result = subprocess.run(
        ["id", "-u", "vhir-smb"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        try:
            subprocess.run(
                [
                    "sudo",
                    "useradd",
                    "-r",
                    "-s",
                    "/usr/sbin/nologin",
                    "-M",
                    "-G",
                    "sift",
                    "vhir-smb",
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create vhir-smb user: {e}") from e
    else:
        subprocess.run(
            ["sudo", "usermod", "-aG", "sift", "vhir-smb"],
            capture_output=True,
            timeout=10,
        )

    # Add current user to sift group
    try:
        subprocess.run(
            ["sudo", "usermod", "-aG", "sift", getpass.getuser()],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to add user to sift group: {e}") from e

    _set_smb_password(join_code)

    # Prompt for wintools IP
    import ipaddress

    wintools_ip = _ask("Enter the Windows machine's IP address: ", "").strip()
    if not wintools_ip:
        if reconfigure_ip:  # the share stays as it is, as with "n"
            _mark_case_for_kept_share()
            return reconfigure_ip
        if not moved_ip:
            return None
        wintools_ip = moved_ip  # the share moves with the IP it had
    try:
        addr = ipaddress.IPv4Address(wintools_ip)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise RuntimeError(f"Invalid IPv4 address: {wintools_ip}") from e
    if not addr.is_private:
        raise RuntimeError(
            f"IP must be a private address (10.x, 172.16-31.x, 192.168.x): {wintools_ip}"
        )

    # The share points at the active case, or at the inactive placeholder
    # when there is none; activation repoints it from then on.
    placeholder = Path.home() / ".vhir" / "share-inactive"
    placeholder.mkdir(parents=True, exist_ok=True)
    active = _active_case_dir()
    share_target = str(active or placeholder)
    check_share_path(share_target)
    if active is not None:  # the share and its marker move together
        warning = mark_case(active)
        if warning:
            print(
                f"Warning: {warning}; wintools writes nothing to the case.",
                file=sys.stderr,
            )

    # Write Samba config — files are written as the installer and their own
    # private group, so the installer can change what wintools wrote without
    # a re-login. Authentication still uses vhir-smb (valid users).
    share = {
        "share_name": SHARE_NAME,
        "smb_user": "vhir-smb",
        "force_user": username,
        "force_group": group,
        "wintools_ip": wintools_ip,
    }
    smb_conf = _share_conf(share, share_target)
    smb_conf_path = SMB_CONF_PATH
    try:
        subprocess.run(
            ["sudo", "mkdir", "-p", "/etc/samba/smb.conf.d"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["sudo", "tee", smb_conf_path],
            input=smb_conf.encode(),
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to write Samba config: {e}") from e

    # Ensure include in smb.conf
    try:
        result = subprocess.run(
            ["sudo", "cat", "/etc/samba/smb.conf"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        include_line = f"include = {smb_conf_path}"
        if include_line not in result.stdout:
            if result.returncode != 0 or not result.stdout.strip():
                # Fresh install — create minimal smb.conf
                minimal = f"[global]\n   workgroup = WORKGROUP\n{include_line}\n"
                subprocess.run(
                    ["sudo", "tee", "/etc/samba/smb.conf"],
                    input=minimal.encode(),
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
            else:
                subprocess.run(
                    ["sudo", "tee", "-a", "/etc/samba/smb.conf"],
                    input=f"\n{include_line}\n".encode(),
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to update smb.conf: {e}") from e

    # Restart smbd
    try:
        subprocess.run(
            ["sudo", "systemctl", "restart", "smbd"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to restart smbd: {e}") from e

    # Create sudoers.d entry for passwordless repoint
    sudoers_content = (
        f"{username} ALL=(root) NOPASSWD: /usr/bin/tee {smb_conf_path}\n"
        f"{username} ALL=(root) NOPASSWD: /usr/bin/smbcontrol smbd reload-config\n"
        f"{username} ALL=(root) NOPASSWD: /usr/bin/smbcontrol smbd close-share {SHARE_NAME}\n"
    )
    try:
        subprocess.run(
            ["sudo", "tee", "/etc/sudoers.d/vhir-samba"],
            input=sudoers_content.encode(),
            check=True,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["sudo", "chmod", "0440", "/etc/sudoers.d/vhir-samba"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to create sudoers entry: {e}", file=sys.stderr)
        print("Case operations may require sudo password.", file=sys.stderr)

    # Write ~/.vhir/samba.yaml
    import datetime

    vhir_dir = Path.home() / ".vhir"
    vhir_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    samba_data = {
        **share,
        "active_share_target": share_target,
        "configured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    samba_path = vhir_dir / "samba.yaml"
    fd = os.open(str(samba_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.dump(samba_data, f, default_flow_style=False)

    print(
        f"Samba share configured: //{_get_sift_ip() or 'SIFT_IP'}/{SHARE_NAME} (per-case)"
    )
    return wintools_ip


def _stop_without_code(step: str, error: Exception, hint: str = "") -> None:
    """A setup step failed: Windows can't use the share as it stands, so the
    code is never shown. The gateway keeps only its hash, and it expires
    unused."""
    print(f"\nError: {step} failed: {error}", file=sys.stderr)
    print(
        "No join code was shown: the Windows installer can't use this SIFT "
        "box until this step works.",
        file=sys.stderr,
    )
    print(
        "Fix the cause above, then run 'vhir setup join-code' again.",
        file=sys.stderr,
    )
    if hint:
        print(hint, file=sys.stderr)
    sys.exit(1)


def _post_join_code_setup(data: dict, static_ip: str | None) -> None:
    """Samba setup, firewall, and display — called after join code generation.
    A code bound to an examiner name joins only that examiner (never a
    wintools host), so it prints the `vhir join` line and sets up nothing."""
    join_code = data["code"]
    try:
        sift_host = static_ip or _get_sift_ip() or _detect_ip()
    except OSError:
        sift_host = static_ip or _get_sift_ip() or "SIFT_IP"

    if data.get("name"):
        from urllib.parse import urlparse

        gw = urlparse(_get_local_gateway_url())  # its scheme too: http or https
        port = gw.port or 4508
        name = data["name"]
        print(f"\nJoin code: {join_code} (expires in {data['expires_hours']} hours)")
        print(
            f"This code joins as {name} only, and ends {name}'s earlier gateway tokens. "
            "Their credential, signing key and ledger lines are unchanged."
        )
        print(f"\nOn {name}'s machine, run:")
        print(
            f"  vhir join --sift {gw.scheme or 'https'}://{sift_host}:{port} --code {join_code}"
        )
        return

    # The installer pins a TLS gateway's certificate by this value: the
    # gateway's CA isn't in the Windows trust store
    from vhir_cli.gateway import get_local_gateway_cert_sha256

    try:
        cert_sha256 = get_local_gateway_cert_sha256()
    except (OSError, ValueError) as e:
        _stop_without_code("Reading the gateway's certificate", e)
    pin = f" -GatewayCertSha256 {cert_sha256}" if cert_sha256 else ""

    try:
        wintools_ip = _setup_samba_share(join_code)
    except Exception as e:
        _stop_without_code("Samba share setup", e)

    if wintools_ip:
        try:
            _setup_firewall(wintools_ip)
        except Exception as e:
            _stop_without_code(
                "Firewall setup",
                e,
                "  Or add the rules by hand: sudo ufw allow from "
                f"{wintools_ip} to any port 4508,445 proto tcp",
            )

    from urllib.parse import urlparse

    gw_url = _get_local_gateway_url()
    gw_port = urlparse(gw_url).port or 4508

    print(f"\nJoin code: {join_code} (expires in {data['expires_hours']} hours)")
    if not wintools_ip:
        print(
            "\nOn each examiner machine: run 'vhir setup client', then /mcp in Claude Code"
        )
        print("No Windows machine: run 'vhir setup join-code' again when you add one.")
        return
    print(
        "\nOn Windows, in PowerShell as Administrator, download the current "
        "installer and run it (one line):"
    )
    # Windows clients ship with script running disabled. The Process scope
    # lasts only for this PowerShell window and is not saved.
    print(
        "  Set-ExecutionPolicy -Scope Process Bypass -Force; cd $env:TEMP; "
        "Invoke-WebRequest "
        "https://github.com/AppliedIR/wintools-mcp/archive/refs/heads/main.zip "
        "-OutFile wintools.zip; if ($?) { Expand-Archive wintools.zip "
        "-DestinationPath . -Force; if ($?) { "
        f".\\wintools-mcp-main\\scripts\\setup-windows.ps1 -JoinCode {join_code} "
        f"-GatewayHost {sift_host} -GatewayPort {gw_port}{pin} }} }}"
    )
    print(
        "  Unattended: add -NonInteractive -AcknowledgeSecurityHole after the port number"
    )
    print(
        "\nWhen the installer has finished: run 'vhir setup client' on each "
        "examiner machine, then /mcp in Claude Code"
    )


def _wintools_ssl_context():
    """Build SSL context for wintools connections using pinned cert.

    Uses SSLContext(PROTOCOL_TLS_CLIENT) instead of create_default_context()
    so that ONLY the pinned cert is trusted (no system CAs).
    """
    import ssl

    cert_path = Path.home() / ".vhir" / "tls" / "wintools-cert.pem"
    if cert_path.exists():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(cert_path))
    else:
        print(
            "Warning: wintools TLS cert not found, skipping verification",
            file=sys.stderr,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _push_smb_credentials(password: str, smb_user: str = "vhir-smb") -> None:
    """Push updated SMB credentials to wintools-mcp after smbpasswd change."""
    import urllib.request
    from urllib.parse import urlparse, urlunparse

    gateway_config = Path.home() / ".vhir" / "gateway.yaml"
    if not gateway_config.is_file():
        return
    try:
        config = yaml.safe_load(gateway_config.read_text())
    except Exception:
        return
    wt = config.get("backends", {}).get("wintools-mcp", {})
    url = wt.get("url", "")
    token = wt.get("bearer_token", "")
    if not url or not token:
        return  # wintools not configured

    parsed = urlparse(url)
    update_url = urlunparse(parsed._replace(path="/config/update-smb"))

    payload = json.dumps({"smb_user": smb_user, "smb_password": password}).encode()
    req = urllib.request.Request(
        update_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    import time as _time

    kwargs: dict = {"timeout": 5}
    if update_url.startswith("https"):
        kwargs["context"] = _wintools_ssl_context()
    last = "no answer"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, **kwargs):
                print("  SMB credentials pushed to wintools-mcp")
                return
        except urllib.error.HTTPError as e:  # wintools answered: say what
            try:
                body = e.read().decode("utf-8", errors="replace").strip()[:300]
            except Exception as read_error:  # a body that never comes
                body = f"(its body couldn't be read: {read_error})"
            last = f"HTTP {e.code}: {body}"
            print(
                f"  wintools-mcp answered the SMB credential push: {last}",
                file=sys.stderr,
            )
        except Exception as e:
            last = str(e) or type(e).__name__
        if attempt < 2:
            _time.sleep(5)
    # wintools may not be running yet (normal during first setup): the Windows
    # installer derives the same password from the join code.
    print(
        f"  Warning: wintools-mcp didn't confirm the new SMB credentials ({last}). "
        "The Windows installer gives them to it when it runs with the join code "
        "'vhir setup join-code' shows.",
        file=sys.stderr,
    )


def notify_wintools_case_activated(case_id: str) -> bool:
    """Notify wintools-mcp of case activation. Non-fatal on failure.

    Returns True if notification succeeded or wintools is not configured.
    Returns False only on actual communication failure.
    """
    import urllib.request
    from urllib.parse import urlparse, urlunparse

    gateway_config = Path.home() / ".vhir" / "gateway.yaml"
    if not gateway_config.is_file():
        return True  # not configured -- not a failure
    try:
        config = yaml.safe_load(gateway_config.read_text())
    except Exception:
        return True  # can't read config -- not a wintools failure
    wt = config.get("backends", {}).get("wintools-mcp", {})
    url = wt.get("url", "")
    token = wt.get("bearer_token", "")
    if not url or not token:
        return True  # wintools not configured -- not a failure

    parsed = urlparse(url)
    activate_url = urlunparse(parsed._replace(path="/cases/activate"))

    payload = json.dumps({"case_id": case_id}).encode()
    req = urllib.request.Request(
        activate_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        kwargs = {"timeout": 10}
        if activate_url.startswith("https"):
            kwargs["context"] = _wintools_ssl_context()
        with urllib.request.urlopen(req, **kwargs):
            pass
        return True
    except (ConnectionError, OSError):
        return False
    except Exception as e:
        print(f"Warning: failed to notify wintools of activation: {e}", file=sys.stderr)
        return False


def notify_wintools_case_deactivated() -> bool:
    """Notify wintools-mcp of case deactivation. Non-fatal on failure.

    Returns True if notification succeeded or wintools is not configured.
    Returns False only on actual communication failure.
    """
    import urllib.request
    from urllib.parse import urlparse, urlunparse

    gateway_config = Path.home() / ".vhir" / "gateway.yaml"
    if not gateway_config.is_file():
        return True  # not configured
    try:
        config = yaml.safe_load(gateway_config.read_text())
    except Exception:
        return True
    wt = config.get("backends", {}).get("wintools-mcp", {})
    url = wt.get("url", "")
    token = wt.get("bearer_token", "")
    if not url or not token:
        return True  # not configured

    parsed = urlparse(url)
    deactivate_url = urlunparse(parsed._replace(path="/cases/deactivate"))

    req = urllib.request.Request(
        deactivate_url,
        data=b"{}",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        kwargs = {"timeout": 10}
        if deactivate_url.startswith("https"):
            kwargs["context"] = _wintools_ssl_context()
        with urllib.request.urlopen(req, **kwargs):
            return True
    except (ConnectionError, OSError):
        return False  # wintools unreachable
    except Exception as e:
        print(
            f"Warning: failed to notify wintools of deactivation: {e}", file=sys.stderr
        )
        return False


def _repoint_samba_share(case_dir: Path | None) -> None:
    """Update the Samba share to point at a specific case directory.

    If case_dir is None, points to an inactive placeholder.
    Uses smbcontrol reload (not smbd restart) for zero-downtime.
    """
    import subprocess

    samba_yaml = Path.home() / ".vhir" / "samba.yaml"
    if not samba_yaml.is_file():
        return  # Samba not configured

    doc = yaml.safe_load(samba_yaml.read_text()) or {}
    current_target = doc.get("active_share_target", "")

    placeholder = Path.home() / ".vhir" / "share-inactive"
    target = str(case_dir) if case_dir else str(placeholder)

    check_share_path(target)  # before the no-op, so a bad tracked target is still said
    if case_dir is not None:  # the share and its marker move together, tracked or not
        warning = mark_case(case_dir)
        if warning:
            print(
                f"Warning: {warning}; wintools writes nothing to the case.",
                file=sys.stderr,
            )
    if target == current_target:
        return  # No-op

    placeholder.mkdir(parents=True, exist_ok=True)

    conf_path = SMB_CONF_PATH
    smb_conf = _share_conf(doc, target)
    try:
        subprocess.run(
            ["sudo", "tee", conf_path],
            input=smb_conf.encode(),
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: failed to write Samba config: {e}", file=sys.stderr)
        return

    # Update tracker AFTER tee succeeds — if tee failed, next call retries.
    doc["active_share_target"] = target
    samba_yaml.write_text(yaml.dump(doc, default_flow_style=False))

    result = subprocess.run(
        ["sudo", "smbcontrol", "smbd", "reload-config"],
        capture_output=True,
        timeout=15,
    )
    if result.returncode != 0:
        print(
            f"Warning: smbcontrol reload failed: {result.stderr.decode().strip()}",
            file=sys.stderr,
        )

    # Force-close existing connections so clients pick up the new path.
    # Windows SMB redirector auto-reconnects using cached LSASS credentials.
    subprocess.run(
        ["sudo", "smbcontrol", "smbd", "close-share", doc.get("share_name") or "cases"],
        capture_output=True,
        timeout=15,
    )


def _detect_current_ip() -> str | None:
    """Detect the current primary IPv4 address via UDP socket trick."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def _ensure_static_ip() -> str | None:
    """Configure static IP via netplan. Returns the static IP or None if skipped."""
    network_yaml = Path.home() / ".vhir" / "network.yaml"
    if network_yaml.is_file():
        try:
            doc = yaml.safe_load(network_yaml.read_text())
            existing_ip = doc.get("static_ip")
            if existing_ip:
                # Verify the interface actually has this IP
                actual_ip = _detect_current_ip()
                if actual_ip == existing_ip:
                    answer = _ask(
                        f"Static IP configured and active: {existing_ip}\n"
                        "Reconfigure? [y/N] ",
                        "n",
                    )
                    answer = answer.strip().lower()
                    if answer not in ("y", "yes"):
                        return existing_ip
                else:
                    answer = _ask(
                        f"Warning: network.yaml says {existing_ip} "
                        f"but interface has {actual_ip or 'unknown'}\n"
                        "The static IP was stored but never applied to the interface.\n"
                        f"Apply {existing_ip} now? [Y/n] ",
                        "n",
                    )
                    answer = answer.strip().lower()
                    if answer in ("", "y", "yes"):
                        ip = existing_ip
                        # Fall through to apply logic below
                    else:
                        answer2 = _ask(
                            "Enter a different IP, or blank to skip: ", ""
                        ).strip()
                        if answer2:
                            ip = answer2
                        else:
                            return None
                    # Skip the detection/prompt section — ip is already set
                    return _apply_static_ip(ip, network_yaml)
        except (yaml.YAMLError, OSError):
            pass

    detected_ip = _detect_current_ip() or ""

    intro = (  # shown with the first question only
        "Remote machines (Windows workstation, LLM clients) connect to this\n"
        "SIFT workstation by IP. A static IP ensures they can reconnect after reboot.\n"
        "\n"
    )
    while True:
        ip = _ask(f"{intro}Enter static IP for this machine [{detected_ip}]: ", None)
        intro = ""
        if ip is None:  # no terminal: no static IP, no netplan change
            return None
        ip = ip.strip()
        if not ip:
            ip = detected_ip
        if not ip:
            print("No IP provided, skipping static IP configuration.", file=sys.stderr)
            return None
        confirm = _ask(f"\n  Static IP: {ip}\n  Correct? [Y/n] ", "n").strip().lower()
        if confirm in ("", "y", "yes"):
            break

    return _apply_static_ip(ip, network_yaml)


def _apply_static_ip(ip: str, network_yaml: Path) -> str | None:
    """Validate IP, write netplan config, apply, write network.yaml."""
    import ipaddress
    import subprocess

    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        print(f"Invalid IPv4 address: {ip}", file=sys.stderr)
        return None
    if not addr.is_private:
        print(
            "IP must be a private address (10.x, 172.16-31.x, 192.168.x)",
            file=sys.stderr,
        )
        return None

    # Detect interface
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        iface = None
        parts = result.stdout.split()
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        if not iface:
            print("Could not detect network interface.", file=sys.stderr)
            return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"Failed to detect network interface: {e}", file=sys.stderr)
        return None

    # Detect prefix length
    prefix = "24"
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                # inet 192.168.1.5/24 ...
                addr_part = line.split()[1]
                if "/" in addr_part:
                    prefix = addr_part.split("/")[1]
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Detect DNS
    dns_servers = []
    try:
        result = subprocess.run(
            ["resolvectl", "status", iface],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "DNS Servers" in line:
                dns_servers = line.split(":", 1)[1].strip().split()
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    if not dns_servers:
        resolv = Path("/etc/resolv.conf")
        if resolv.is_file():
            for line in resolv.read_text().splitlines():
                if line.strip().startswith("nameserver"):
                    dns_servers.append(line.strip().split()[1])
    if not dns_servers:
        dns_servers = ["8.8.8.8", "1.1.1.1"]

    # Detect gateway
    gateway = ""
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    gateway = parts[parts.index("via") + 1]
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Pre-check existing netplan configs
    import glob

    existing_configs = glob.glob("/etc/netplan/*.yaml")
    conflicting = []
    for cfg_path in existing_configs:
        if "99-vhir-static" in cfg_path:
            continue
        try:
            with open(cfg_path) as f:
                cfg_doc = yaml.safe_load(f)
            if cfg_doc and "network" in cfg_doc:
                ethernets = cfg_doc["network"].get("ethernets", {})
                if iface in ethernets:
                    conflicting.append(cfg_path)
        except (yaml.YAMLError, OSError):
            pass
    if conflicting:
        listed = "".join(f"  {c}\n" for c in conflicting)
        answer = _ask(
            f"Warning: existing netplan configs for {iface}:\n{listed}"
            "Override with Valhuntir static config? [y/N] ",
            "n",
        )
        answer = answer.strip().lower()
        if answer not in ("y", "yes"):
            print("Skipped static IP configuration.", file=sys.stderr)
            return None

    # Write netplan config
    routes_block = ""
    if gateway:
        routes_block = f"""      routes:
        - to: default
          via: {gateway}
"""
    netplan_content = f"""network:
  version: 2
  ethernets:
    {iface}:
      dhcp4: false
      addresses:
        - {ip}/{prefix}
{routes_block}      nameservers:
        addresses: [{", ".join(dns_servers)}]
"""
    try:
        subprocess.run(
            ["sudo", "tee", "/etc/netplan/99-vhir-static.yaml"],
            input=netplan_content.encode(),
            capture_output=True,
            check=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to write netplan config: {e}", file=sys.stderr)
        return None

    # Apply netplan
    try:
        subprocess.run(
            ["sudo", "netplan", "apply"],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply netplan: {e}", file=sys.stderr)
        print(
            "Review /etc/netplan/99-vhir-static.yaml and apply manually.",
            file=sys.stderr,
        )
        return None

    # Write ~/.vhir/network.yaml
    import datetime

    vhir_dir = Path.home() / ".vhir"
    vhir_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    network_data = {
        "static_ip": ip,
        "interface": iface,
        "configured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    fd = os.open(str(network_yaml), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.dump(network_data, f, default_flow_style=False)

    # Verify gateway health
    from vhir_cli.gateway import get_local_gateway_url, get_local_ssl_context

    health_url = f"{get_local_gateway_url()}/health"
    ssl_ctx = get_local_ssl_context()
    try:
        import urllib.request

        kwargs = {"timeout": 5}
        if ssl_ctx is not None:
            kwargs["context"] = ssl_ctx
        with urllib.request.urlopen(health_url, **kwargs) as resp:
            if resp.status == 200:
                print(f"Static IP set to {ip}, gateway healthy.")
                return ip
    except OSError:
        pass

    print(
        f"Static IP set to {ip}. Gateway health check inconclusive — verify manually."
    )
    return ip
