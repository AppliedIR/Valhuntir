"""Configuration management."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from vhir_cli import credentials


def _credential(action, name: str, config_path: Path, **kw) -> None:
    try:
        action(name, config_path, **kw)
    except credentials.CredentialError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_enrol(args, identity: dict) -> None:
    """`vhir enrol --name NAME [--reset | --forgot | --upgrade]`: a LAN
    examiner's credential, set up at this terminal by the person named."""
    from vhir_cli.identity import valid_name

    config_path = Path.home() / ".vhir" / "config.yaml"
    name = args.name
    if not valid_name(name):
        print(
            f"Invalid examiner name: {name!r} (lower-case letters, digits and hyphens, "
            "at most 20 characters)",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.reset:
        _credential(credentials.reset, name, config_path)
    elif args.forgot:
        _credential(credentials.forgot, name, config_path)
    elif args.upgrade:
        _credential(credentials.upgrade, name, config_path)
    else:
        _credential(credentials.enrol, name, config_path, by_name=True)


def cmd_config(args, identity: dict) -> None:
    """Configure Valhuntir settings."""
    config_path = Path.home() / ".vhir" / "config.yaml"
    examiner = identity["examiner"]

    if getattr(args, "setup_password", False):
        _credential(credentials.enrol, examiner, config_path)
        return
    if getattr(args, "reset_password", False):
        _credential(credentials.reset, examiner, config_path)
        return
    if getattr(args, "forgot_password", False):
        _credential(credentials.forgot, examiner, config_path)
        return
    if getattr(args, "upgrade_key", False):
        _credential(credentials.upgrade, examiner, config_path)
        return

    if args.show:
        if config_path.exists():
            try:
                content = config_path.read_text()
                # Redact legacy password/PIN material during transition
                try:
                    config = yaml.safe_load(content)
                    if isinstance(config, dict):
                        for key in ("passwords", "pins"):
                            if key in config:
                                config[key] = {k: "***REDACTED***" for k in config[key]}
                        content = yaml.dump(config, default_flow_style=False)
                except yaml.YAMLError:
                    pass
                print(content)
            except OSError as e:
                print(f"Failed to read configuration file: {e}", file=sys.stderr)
        else:
            print("No configuration file found.")
            print(
                f"Current identity: {identity['examiner']} (source: {identity['examiner_source']})"
            )
        return

    examiner_val = getattr(args, "examiner", None)
    if examiner_val:
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(
                f"Failed to create config directory {config_path.parent}: {e}",
                file=sys.stderr,
            )
            return

        config = {}
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                print(
                    f"Warning: existing config is invalid YAML ({e}), overwriting.",
                    file=sys.stderr,
                )
                config = {}
            except OSError as e:
                print(
                    f"Warning: could not read existing config ({e}), creating new.",
                    file=sys.stderr,
                )
                config = {}

        config["examiner"] = examiner_val
        # Remove deprecated 'analyst' key if present
        config.pop("analyst", None)

        try:
            from vhir_cli.case_io import _atomic_write

            _atomic_write(config_path, yaml.dump(config, default_flow_style=False))
        except (OSError, yaml.YAMLError) as e:
            print(f"Failed to write configuration: {e}", file=sys.stderr)
            return
        print(f"Examiner identity set to: {examiner_val}")
        return

    print(
        "Use --examiner <name> to set identity, --show to view config, --setup-password to set the signing passphrase."
    )
