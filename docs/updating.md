# Updating

How to update an existing Valhuntir install. Do the steps in this order: SIFT first, then the Windows workstation, then any remote examiner machines.

## 1. Update the SIFT workstation

Run `vhir update` on the SIFT workstation, in your own terminal:

```bash
vhir update --check      # Show how many commits each repo is behind; no pull, reinstall or restart
vhir update              # Pull, reinstall, redeploy the client controls, restart the gateway
```

| Option | Description |
|--------|-------------|
| `--check` | Check for updates without applying |
| `--no-restart` | Skip the gateway restart |
| `--cpu` | Install CPU PyTorch for knowledge search (~0.7 GB) |
| `--gpu` | Install GPU (CUDA) PyTorch for knowledge search (~5.4 GB) |

`--check` fetches each repo and shows how many commits it is behind. It does not pull, reinstall or restart anything, but like a full update it first updates `uv` itself (`uv self update`).

`--cpu` and `--gpu` choose the PyTorch build that knowledge search uses. Without either, the update keeps the build already installed (CPU if there is none). On a terminal it may ask once, when no choice has been recorded.

The update pulls sift-mcp, vhir and, if it is installed, opensearch-mcp. It then reinstalls the packages, redeploys the forensic controls, restarts the gateway and runs a connectivity check. It needs the SIFT install that `setup-sift.sh` made (`~/.vhir/manifest.json`), and it updates only this machine.

If the installed OpenSearch is older than the version this release expects, the update offers to upgrade it. The indexed data is kept, and case records are not affected.

## 2. What the update redeploys for each client

The update redeploys the controls of each client recorded in `~/.vhir/manifest.json` on this machine:

| Client | What the update redeploys |
|--------|---------------------------|
| Claude Code | The forensic controls: settings, rules, hooks and sandbox. It prints what the settings file holds now. |
| Codex | Valhuntir's profile and skills, and the managed requirements (`/etc/codex/requirements.toml`). If you opted out of those controls (a machine set up for Codex with no requirements file), the update leaves them off and prints their state. |
| Claude Desktop | Nothing. The update prints that Claude Desktop is no longer supported, because the commands it runs aren't audited. Use Claude Code, or Codex. |
| LibreChat and other MCP clients | Nothing: they have no local controls. They reach the gateway as before. |

Then restart Claude Code or Codex so it picks up the new rules. A Claude Code session that stays open loses its tool connections when the gateway restarts: run `/mcp` in it, or restart it.

The README's "What changes for AI clients in this release" section lists what a redeploy changes in this release.

## 3. Update the Windows workstation

Update SIFT first, then join wintools again with a new join code:

1. On SIFT: `vhir update`, then `vhir setup join-code`. It can ask for the Windows machine's IP address, and prints a one-line PowerShell command.
2. On Windows, in PowerShell as Administrator: run that line. It downloads the current installer and runs `setup-windows.ps1 -JoinCode <code> -GatewayHost <sift-ip> -GatewayPort 4508`.

A wintools-mcp updated before SIFT re-joins writes nothing to the case ("the evidence share has no case marker"). It writes again after the re-join, or after the case is activated again on SIFT (`vhir case activate <case>`).

## 4. Update a remote examiner machine

`vhir update` does not reach a remote examiner machine. An examiner machine set up with `setup-client-linux.sh`, `setup-client-macos.sh` or `setup-client-windows.ps1` gets the new controls when the setup script runs again with a new join code:

1. On SIFT: `vhir setup join-code --name <examiner>`. The code joins under that examiner's name and ends that name's earlier gateway tokens.
2. On the examiner machine: download the setup script again and run it with `--sift=https://<sift-ip>:4508 --code=<code>` (on Windows, `-Sift https://<sift-ip>:4508 -Code <code>`), as in [Deployment](deployment.md). With `--sift` the script fetches the current forensic controls from GitHub.

An examiner machine that has vhir installed can run `vhir setup client --remote --sift=https://<sift-ip>:4508 --token=<token>` instead. For Claude Code, that command copies the controls from the machine's local sift-mcp source (such as `~/.vhir/src/sift-mcp`), so update that source first or it redeploys the old controls. For Codex (`--client=codex`), it fetches the instructions, skills and finding-skeptic agent from sift-mcp's main branch on GitHub, so the machine needs network access. If the instructions can't be fetched, the Codex profile isn't written. Do this after any update whose release notes change the client controls.

## 5. After the update

The update ends with the examiner's signing status:

- **A 0.6 passphrase:** approvals need a signing key now. The update offers to make one. To do it later, run:

  ```bash
  vhir config --upgrade-key
  ```

- **No passphrase:** set one with `vhir config --setup-password`.
- **A signing key:** the update prints its fingerprint.

Items approved before 0.6.4 have no signed approval line. To sign a fresh approval of them:

```bash
vhir approve --reattest F-alice-005      # Specific IDs
vhir approve --reattest --all            # Every item it applies to
```

A LAN examiner who enrolled at the SIFT terminal uses `vhir enrol --name <examiner> --upgrade` for a 0.6 passphrase.
