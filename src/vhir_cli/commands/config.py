"""Configuration management."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from vhir_cli.approval_auth import reset_password, setup_password


def cmd_config(args, identity: dict) -> None:
    """Configure ValiHuntIR settings."""
    config_path = Path.home() / ".vhir" / "config.yaml"

    if getattr(args, "setup_password", False):
        setup_password(config_path, identity["examiner"])
        return

    if getattr(args, "reset_password", False):
        reset_password(config_path, identity["examiner"])
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
        "Use --examiner <name> to set identity, --show to view config, --setup-password to configure password."
    )
