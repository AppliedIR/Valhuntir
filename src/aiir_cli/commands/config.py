"""Configuration management."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from aiir_cli.approval_auth import reset_pin, setup_pin


def cmd_config(args, identity: dict) -> None:
    """Configure AIIR settings."""
    config_path = Path.home() / ".aiir" / "config.yaml"

    if getattr(args, "setup_pin", False):
        setup_pin(config_path, identity["examiner"])
        return

    if getattr(args, "reset_pin", False):
        reset_pin(config_path, identity["examiner"])
        return

    if args.show:
        if config_path.exists():
            try:
                content = config_path.read_text()
                # Redact legacy PIN material during transition
                try:
                    config = yaml.safe_load(content)
                    if isinstance(config, dict) and "pins" in config:
                        config["pins"] = {k: "***REDACTED***" for k in config["pins"]}
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
            from aiir_cli.case_io import _atomic_write

            _atomic_write(config_path, yaml.dump(config, default_flow_style=False))
        except (OSError, yaml.YAMLError) as e:
            print(f"Failed to write configuration: {e}", file=sys.stderr)
            return
        print(f"Examiner identity set to: {examiner_val}")
        return

    print(
        "Use --examiner <name> to set identity, --show to view config, --setup-pin to configure PIN."
    )
