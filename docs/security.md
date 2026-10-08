# Security Model

## Design Philosophy

Valhuntir runs on isolated forensic workstations behind firewalls. The primary security boundary is network isolation and VM/container isolation, not in-band command filtering. The controls described here are defense-in-depth measures within that boundary.

## Network Assumptions

All Valhuntir components are assumed to run on a private forensic network:

- Not exposed to incoming connections from the Internet
- Not exposed to untrusted systems
- Protected by firewalls on a trusted network segment
- Outgoing Internet connections are required for report generation (Zeltser IR Writing MCP) and optionally for threat intelligence (OpenCTI) and documentation (MS Learn MCP)

wintools-mcp must only be installed on dedicated forensic workstations. Never install on personal laptops, production systems, or machines containing data outside the scope of the investigation.

## Authentication

### Gateway (sift-gateway)

Bearer token authentication on all MCP and REST endpoints (health check excepted). Tokens use the `vhir_gw_` prefix with 24 hex characters (96 bits of entropy).

```text
Authorization: Bearer vhir_gw_a1b2c3d4e5f6a1b2c3d4e5f6
```

API keys map to examiner identities in `gateway.yaml`. The examiner name is injected into backend tool calls for audit attribution.

When installed with `--remote`, TLS is enabled with a local CA certificate.

### wintools-mcp

Bearer token authentication with `vhir_wt_` prefix. Generated during installation. Every request requires `Authorization: Bearer <token>`. The `--no-auth` flag is for development only.

## Execution Security

### sift-mcp (Linux)

- **Denylist**: Blocks destructive system commands (mkfs, dd, fdisk, shutdown, etc.). When Claude Code is the client, additional case-file-specific deny rules are deployed (see L3 below).
- **subprocess.run(shell=False)**: No shell, no arbitrary command chains
- **Argument sanitization**: Shell metacharacters blocked
- **Path validation**: Kernel interfaces (/proc, /sys, /dev) blocked for input
- **rm protection**: Case directories protected from deletion
- **Output truncation**: Large output capped
- **Flag restrictions**: Certain tools have specific flag blocks (find blocks `-exec`/`-delete`, sed blocks `-i`, tar blocks extraction/creation, etc.)

Uncataloged tools can execute with basic response envelopes. Catalog enrollment is for FK enrichment, not access control.

### wintools-mcp (Windows)

- **Catalog allowlist**: Only tools defined in YAML catalog files can execute
- **Hardcoded denylist**: 20+ dangerous binaries blocked (cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, bash, wsl, sh, msbuild, installutil, regasm, regsvcs, cmstp, control — including .exe variants)
- **subprocess.run(shell=False)**: No shell, no command chains
- **Argument sanitization**: Shell metacharacters, response-file syntax (`@filename`), dangerous flags, and output redirect flags all blocked
- **Output directory control**: Zimmerman tool wrappers hardcode the output directory; user-supplied flags cannot override it

The installer requires typing `security_hole` (or passing `-AcknowledgeSecurityHole`) as an intentional friction point.

## Human-in-the-Loop Controls

Nine layers of defense-in-depth protect the integrity of forensic findings. The signed decision ledger (L2) records every examiner decision with a signature that verification checks; what a verified result does and doesn't show is in [Stated limits](#stated-limits). The other layers are advisory controls that raise the bar.

### L1 — Structural Approval Gate

All findings and timeline events stage as DRAFT. Only a human examiner can move them to APPROVED or REJECTED. There is no MCP tool for approval. Every decision is signed with the examiner's own signing key, which only their passphrase unlocks: at the vhir CLI the passphrase is typed at the terminal; in the Examiner Portal the browser unlocks the key and signs, and the passphrase never leaves the browser. The gateway checks every signature before it changes anything.

### L2 — Signed Decision Ledger

Each examiner has an Ed25519 signing key. The private key is stored only encrypted (AES-256-GCM) under a key derived from the examiner's passphrase (PBKDF2-SHA256, 600,000 iterations), in `/var/lib/vhir/keys/{examiner}.json`, beside a separate login verifier.

Every decision (approve, reject, edit, re-attest, and each item decided with it) is one line in the case's ledger, `/var/lib/vhir/ledger/{case-id}.jsonl`, outside the case directory:

- Each line signs the decision and the item's content at that moment, and names the hash of the line before it, so the lines form a chain. The first line also fixes the 0.6 approval records beside it by length and hash.
- `vhir_cli.ledger` is the only writer. Every writer of a case's findings, timeline and IOCs, and of the ledger, holds the case lock (`{case-id}.lock` beside the chain) from load to save.
- Before you sign, every decision is displayed, including each item decided with another ("cascade from F-…"). What is displayed is what is signed.
- After each signed decision, vhir prints the ledger head (sequence and hash) and your key's fingerprint.
- `vhir review --verify` checks every line's signature and link, and each approved item against its latest line. It needs no passphrase. Optional anchors (`--expect-key` for fingerprints, `--expect-head` for heads) let it say `anchored`. Without them it prints "Not anchored", every signing key with its full fingerprint, and each chain's head.
- Close, export and backup write the case's own copies of its signed history into the case (`ledger/`), so the case verifies on another machine.
- Approvals made under 0.6 show as "approved under 0.6 (before signing)". `vhir approve --reattest` (optional) adds a signed approval of the current content.
- `vhir config --reset-password` re-encrypts the same key under a new passphrase. `vhir config --forgot-password` makes a new key and keeps the old public key as retired; earlier approvals keep verifying under it.

### L3 — Case Data Deny Rules

When Claude Code is the LLM client, deny rules block its Edit and Write tools on case data and control files, and its Read tool on `/var/lib/vhir`:

- Case data: `findings.json`, `timeline.json`, `approvals.jsonl`, `todos.json`, `CASE.yaml`, `actions.jsonl`, `audit/*.jsonl`, `evidence.json`, `pending-reviews.json`
- System: `/var/lib/vhir/**` (the ledgers, the signing keys and the passphrase verifiers)
- CLI: `Bash(vhir approve*)` and `Bash(vhir reject*)` (including path-qualified variants)
- Control files: `.claude/settings.json`, `.claude/CLAUDE.md`, `.claude/rules/**`, `.vhir/hooks/**`, `.vhir/active_case`, `.vhir/gateway.yaml`, `.vhir/config.yaml`, `.vhir/.password_lockout`

These rules replace the previous generic denylist (rm -rf, mkfs, dd) with targeted protection for case integrity.

### L4 — Sandbox Filesystem Write Protection

`sandbox.filesystem.denyWrite` uses bwrap to OS-enforce write blocking on protected paths. Bash commands run inside the sandbox cannot modify these files regardless of the shell construct used (sed -i, perl -i, redirections, etc.). Protected paths include `~/.vhir/gateway.yaml`, `~/.vhir/config.yaml`, `~/.vhir/active_case`, `~/.vhir/hooks`, `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, and `~/.claude/rules`. MCP backends run outside the sandbox and can write case data normally.

### L5 — File Permission Protection

Case data files with forensic value (findings.json, timeline.json, approvals.jsonl) are set to chmod 444 (read-only) after every write. The owning process unlocks before writing and relocks after. This is a speed bump, not a wall — the LLM process can chmod — but combined with deny rules and the PreToolUse hook it adds another layer.

At case initialization, the filesystem is checked. Non-POSIX filesystems (NTFS, exFAT, VFAT) trigger a warning since chmod has no effect.

### L6 — One Verdict Source

Every place that says whether an approval holds takes it from the same verification as `vhir review --verify`:

- Reports (report-mcp and `vhir report`) list as approved only the items that verify, and those approved under 0.6 (labelled). Every other APPROVED item is listed as not verified, with its status.
- Every report profile, every saved report and every export carries the case's signing keys with their full fingerprints and each chain's head. A copy that leaves this machine is an anchor you can compare with later.
- `save_report` appends a verification block made by the server.
- The Examiner Portal's badges come from the same verification. A valid item's badge reads `valid (not anchored)`; a finding's Integrity panel adds "Valid (not anchored): compare the fingerprint with a copy kept off this machine." with the key of its signing line.
- An IOC's sources, sightings, confidence and MITRE techniques are derived from the findings that cite it and aren't signed; reports and the portal label them so.

### L7-L8 — Integrity Controls

- **Passphrase and signing key**: Both `vhir approve` and the Examiner Portal sign each decision with the examiner's own key. The CLI reads the passphrase from `/dev/tty`. In the portal the browser signs in with a challenge-response (the passphrase never leaves the browser), then unlocks the key and signs the exact decisions it displayed. Each examiner enrols once with `vhir config --setup-password` (or `vhir enrol --name NAME` at the SIFT terminal for a LAN examiner): at least 8 characters, 15 or more recommended.
- **Provenance enforcement**: Findings must be traceable to evidence (MCP > HOOK > SHELL > NONE). NONE provenance with no supporting commands is rejected by a hard gate in `record_finding()`.
- **Content hash integrity**: SHA-256 hashes computed at staging, checked at review, so a decision staged in the portal isn't signed over content that changed since. `vhir review --verify` checks each approved item against its signed line.

### L9 — Kernel Sandbox (bubblewrap)

Claude Code's sandbox uses bubblewrap (`bwrap`) to isolate Bash commands in
Linux namespaces. It enforces network isolation (`--unshare-net`) and PID
namespace isolation (`--unshare-pid`), plus filesystem write restrictions
(only the working directory is writable). MCP servers run outside the sandbox
with full access. Only Bash commands and their children are confined.

On non-setuid bwrap (all Ubuntu 18.10+), namespace creation requires
unprivileged user namespace support in the kernel. Multiple mechanisms can
block this:

| Mechanism | Versions | Detection |
|-----------|----------|-----------|
| AppArmor `restrict_unprivileged_userns` | Ubuntu 23.10+ | sysctl check + AppArmor profile fix |
| `unprivileged_userns_clone=0` | Any (hardened kernels, cloud images) | sysctl check + persistent fix |
| Container restrictions | Any | `systemd-detect-virt` + marker files + cgroup check |
| WSL1 | Any | `uname -r` check |
| `max_user_namespaces=0` | Any | sysctl check |

`setup-sift.sh` detects these restrictions at install time and provides
environment-specific remediation. On Ubuntu 23.10+, it writes a targeted
AppArmor profile at `/etc/apparmor.d/bwrap` that grants only `/usr/bin/bwrap`
the `userns` permission. On older systems with `unprivileged_userns_clone=0`,
it provides the sysctl command to re-enable user namespaces.

`vhir setup test` includes a sandbox health check with the same diagnostic
cascade.

If the sandbox cannot be enabled (e.g., containers without privileged
namespaces), Claude Code's `enableWeakerNestedSandbox` setting provides
partial isolation (network + filesystem restrictions remain, process
isolation is reduced). By default, `allowUnsandboxedCommands: false` means
Claude Code will refuse to run Bash commands rather than running them
unsandboxed.

### Provenance Tiers

| Tier | Source | Trust Level |
|------|--------|-------------|
| MCP | MCP audit log | System-witnessed |
| HOOK | Claude Code hook log | Framework-witnessed |
| SHELL | `supporting_commands` parameter | Self-reported |
| NONE | No audit record | Rejected |

### Claude Code Controls

When Claude Code is the LLM client, `vhir setup client --client=claude-code` deploys:

- **Kernel-level sandbox**: Restricts Bash writes and network access via bubblewrap (L9). On Ubuntu 24.04+, requires AppArmor profile installed by `setup-sift.sh`
- **Case data deny rules**: Edit and Write blocked on protected case files, the evidence registry and control files, and Read blocked on `/var/lib/vhir` (the verification ledger and password files) (L3)
- **PreToolUse case-data guard**: Refuses Bash commands that would delete or overwrite case records (findings, timeline, approvals, IOCs, evidence registry, TODOs, CASE.yaml, actions, pending reviews), `audit/` or evidence files, or `/` and the folders above the cases root (such as `~`): `rm`, `mv`, `cp`, `truncate`, `shred`, `unlink`, redirections and `find -delete`, seen through `sudo`, `env`, chains, newlines, `$(...)` and `cd`. Moving other files into `DELETE/`, filing new evidence and work in `reports/` are allowed. It is a best-effort check of those commands, not a security boundary: it does not see into `bash -c`, `xargs`, scripts, `tee`, in-place editors (`sed -i`, `perl -i`), `git clean`, `rsync --delete`, `dd of=`, `>&`, brace expansion, variables, backquotes, a quoted `"$(...)"` or an operand after a `$(...)` inside an argument, nor anything after a `#` comment (on later lines too), nor `timeout -s`/`env -u` options, an option value placed after the operands of `cp`, `install` or `ln` (`--suffix .bak`, `-m 0644`), a single-operand `ln` (the link is created in the current folder) or a `cd` inside a subshell or one that fails, and it reads a quoted `'>'` as a redirection (a false block), blocks `find` with `-exec` or `-delete` rooted at `/` or a folder above the cases root whatever its predicates (`find ~ -exec grep …` too), and can misread a quoted `'x$'` before `\(` as a `$(`; and it guards only cases under `$VHIR_CASES_DIR` (default `~/cases`)
- **PostToolUse audit hook**: While a case is active, records each Bash command and its output to the case's `audit/claude-code.jsonl` (with no active case, it records nothing)
- **Provenance enforcement**: Findings without an evidence trail are rejected
- **Signed human approval**: Every decision is signed with the examiner's key, unlocked by their passphrase (L2)

## What a Verified Result Shows

Valhuntir assumes the AI client keeps administrative rights (sudo) on this machine. Under that assumption:

- An anchored exit 0 from `vhir review --verify` shows that each chain presented ends at the head you supplied, and that every line in it was signed with a key you pinned, within its range.
- It shows that you approved that content only if all of these hold: neither your password nor the signing key had been exposed, in the session that made the line or in any earlier session in which the key was unwrapped or the password typed; the code that displayed the items and signed them was unmodified in that session (limit 3); and the heads and fingerprints are your own records kept off this machine, or fingerprints and heads in a report, export or backup that left it before the line was made, checked off this machine (limits 1, 7 and 8).
- A copy of the key, or a password that was observed or guessed (limit 2), can sign lines later without a session of yours, and those lines verify.
- Rotating the key (`--forgot-password`) stops it from making lines that verify after its `supersedes` record. It doesn't invalidate lines signed before that record. A `supersedes` record is written only in chains where the retired key has lines. Elsewhere only your pins exclude the old key, so don't pin a retired key without a range.

## Stated Limits

1. **What a pass shows.** Exit 0 means that every APPROVED item is VALID, or approved under 0.6 (before signing), and that there's no failure. An anchored exit 0 means also that every chain presented is intact and ends at the `--expect-head` you supplied, and that every signing key is pinned with `--expect-key` within its range; verify then prints `anchored`.
   - Verify can't tell where the pins and heads came from. The result is evidence of your approval of that content, while the display and signing code was unmodified (limit 3), only when they are your own records kept off this machine, or fingerprints and heads in a report, export or backup that left it before the line was made, and the check runs off this machine (limits 7 and 8).
   - Making a line that verifies requires the examiner's password (typed, observed or guessed; limits 2 and 3) or a copy of the signing key. A key copied while it was unwrapped in any earlier session stays usable. A password observed at enrolment, reset, upgrade or any approval stays usable until the key is rotated.
   - A cascaded line, `VALID (cascade from F-…)`, shows that the same key signed it with the same `at` as the source decision, at a higher seq. That it was listed before signing is a property of unmodified code (limit 3). Verify prints the source item's current status beside it.
   - Without both anchors, or when a supplied head isn't its chain's last line, the result can still be exit 0, and verify prints "Not anchored: to prove this independently of this machine, compare the key fingerprint with a copy kept off it (any earlier report, export or backup)."
   - Exit 0 without anchors shows that the case files and the ledger on this machine agree with each other. It doesn't show that the keys that signed them are the examiners' own: files on this machine can contain a key no examiner made. Comparing the printed fingerprints with a copy that left this machine earlier (a report, export or backup), or passing them with `--expect-key`, shows that.
2. **Offline guessing.**
   - The verifier and the wrapped key can be read and written by processes running as the examiner.
   - Any copy of a 0.6 password file (a backup or any other copy) stays an offline-guessing target for the examiner's passphrase if it was kept at upgrade; fresh salts don't change that. From this release, backups carry public keys only.
   - Serving the wrapped key only after a verified portal login protects it from gateway-token holders, not from processes that read `/var/lib/vhir/keys/` directly.
   - The minimum is 8 characters, as in 0.6; 15 or more is recommended, and the examiner chooses. A short passphrase, or one built from common words, names or patterns, can be guessed offline from these files in practical time. A randomly generated passphrase of four or more words makes that impractical. A guessed passphrase can sign lines that verify. If a passphrase may have been guessed, run `--forgot-password` to replace the key.
   - Any gateway token holder can post wrong portal responses and use up an examiner's attempts, as in 0.6. That blocks the examiner's approvals for the lockout period; it doesn't produce one.
3. **Code and memory on this machine.** The code that displays items, takes the password and signs runs on, or is served from, this machine. Any process with administrative rights, or modified code, can observe the password, use or copy the signing key while it's in use, or sign content other than what was displayed. A line made that way verifies VALID, and so do lines made later with a copied key or an observed password. This build doesn't protect against that, or detect it, while the AI keeps sudo.
   - The CLI prompt and the portal page are files the examiner account can write.
   - The portal's frozen snapshot and the CLI's re-plan under the lock protect against changes made after the display. Whatever the files held when the display was built is displayed (not every signed field, unless `--show-signed` or the portal's "show all signed fields" toggle is used; limit 6), and is signed if you confirm it.
   - Valhuntir's Claude Code settings deny `vhir approve` and `vhir reject` to the assistant's shell tool. This guards against an accidental or instructed run. It doesn't stop a process with administrative rights, or a program that drives vhir through a pseudo-terminal.
4. **Key changes.**
   - `--forgot-password` creates a new key and keeps the old public key as a retired record. The new key's first line in each case ledger carries a signed `supersedes` record.
   - Lines signed with a superseded key after that record fail `RETIRED_KEY_USE`. That holds for the ledger presented: a copy cut back to before the record shows no retirement. The seq-bounded pin `--forgot-password` prints, and a head recorded after the new key's first line, cover that case.
   - A key you didn't pin is listed under "Not anchored": an examiner with no pin at all as "no key list for examiner X", and an unpinned key of an examiner you did pin with its fingerprint and seqs. "Signing keys:" lists every key with its fingerprint and its first and last seq. Compare them with an earlier report, export or backup.
   - When one examiner has more than one key in the chains presented, verify warns "Key changed at seq N without the previous key's signature" and exits 2, unless every one of that examiner's keys is pinned with `--expect-key`. Every new key warns this way, including one made by `--forgot-password`.
   - Valhuntir commands never replace a key without a retired record. The file itself stays writable (limit 2).
   - A password change re-wraps the same key; it doesn't revoke it. If the password or key may have been exposed, use `--forgot-password`.
   - Rotating a key doesn't invalidate lines already signed with it. Lines signed with an exposed key before its `supersedes` record still verify. Bounded pins (`:FROM-TO`) limit which seqs you accept for that key.
5. **Truncation and restore.**
   - Removing lines from the end of a chain, or restoring an older backup, is detected against a recorded head: with your most recent head, verify says `anchored` only if the chain ends exactly there, and otherwise lists the later lines. Without a head, removal from the end isn't detected, and the result can be exit 0. Removing a whole chain copy is detected only if you supply that chain's head.
   - Removal or reordering elsewhere in a chain is detected when every key that signed it is pinned and wasn't exposed.
   - A pinned head fixes every body, and so every key, at or before its seq.
6. **What a VALID line covers.** It covers the signed view of the item at decision time: every field except `status`, `approved_at`, `approved_by`, `rejected_at`, `rejected_by`, `rejection_reason`, `examiner_notes`, `examiner_modifications`, `content_hash`, `verification`, `modified_at`, `provenance`, `provenance_warnings`, `source_evidence` and `reattested_*`, and for IOCs also `source_findings`, `sightings`, `confidence` and `mitre_techniques`.
   - Unsigned: the examiner's note, the rejection reason, and the record of original values in `examiner_modifications`. The edited values themselves are signed as part of the item.
   - The four derived IOC fields come from every citing finding, DRAFT and rejected included. They are labelled "derived, not signed".
   - The signature covers the whole recorded item, including fields the display may not show (for example `artifacts`).
   - A cascaded line is signed by the same key, with the same `at`, as its source decision, at a higher seq, and its link is checked (`CASCADE_UNSUPPORTED` otherwise). That it was listed before signing is a property of unmodified code (limit 3).
7. **Anchors.** An anchor is a fingerprint (or head) held somewhere this machine can't change: a report, export or backup that has left it, or a note you made. Every report and export prints the signing keys and fingerprints, so each copy that leaves the machine anchors the keys as of the time it left. A copy still on this machine isn't an anchor. A copy made after a key change carries the changed fingerprint, so compare with the earliest copy you have. Pass fingerprints with `--expect-key`, and heads with `--expect-head`, to have verify print `anchored`. A verdict is independent of this machine only when it's run off it (limit 8).
   - A saved report ends with a verification block that the server appends. How a viewer renders the report depends on the content above the block (an unclosed HTML comment, for example, can hide it); the raw file and `vhir review --findings --verify` are authoritative.
8. **Verification code.**
   - Verification runs Valhuntir's own code.
   - A check that doesn't depend on this machine copies the case directory after close (which writes the chain copies) to a clean Valhuntir install on another machine, and runs `vhir review --findings --verify` there, with your own `--expect-key` and `--expect-head`.
   - `--ledger PATH` (repeatable) reads only the given chain copies, instead of this machine's chain and the case's copies.
   - No separate verifier ships in this release.
9. **Approvals made under 0.6** show as "approved under 0.6 (before signing)". They carry no signature that 0.7 can check. They record that an approval was made, not who made it. Once a case has its first signed line, its 0.6 records are fixed by length and hash, and a 0.6-format record added later doesn't count: an APPROVED item whose only support it is fails as `APPROVED_NO_LINE`. In a case with no signed line yet, a file write can add or remove such a record. `vhir approve --reattest` (optional) adds a signed approval of the current content, dated now; the original record is unchanged.
10. **Clocks.** `at`, `created_at` and retired dates come from the signer's local clock and aren't verified. Order comes from `seq` within a chain, and across chains from the signed `prior_chains` references.
11. **Status counters and labels.**
    - Status counters and status-only displays (`vhir case status`, `get_case_status`, `/api/summary`, forensic-mcp `get_findings`/`get_timeline`, `vhir review --iocs` grouping, the portal's "By <approved_by>") are based on status and aren't verification. report-mcp's approved-findings count comes from verification.
    - The pending-reviews file is shared by everyone who holds a gateway token for the case. An entry's `staged_by` records who posted it, as stamped by the gateway; it is a label, not a verified identity.
    - `saved_unsigned` is also a label. Any writer of the case directory can set it, so "saved unsigned from the CLI" doesn't show that the CLI saved the entry. Entries posted with an examiner's gateway token, including by an MCP client using that token, are labelled as that examiner's own.
    - The box owner's gateway token is also the token that local MCP clients use. Whoever holds it can mint a join code bound to any LAN examiner's name except the owner's. A join with that code gets a gateway token under that name and ends that name's earlier tokens. That token can stage entries labelled as that examiner's, and can use up that examiner's attempts (limit 2). It can't sign as them: signing needs that examiner's passphrase or key, and a join changes neither.
12. **Collaboration.** Approvals don't travel through bundle import (`vhir merge`, case-mcp `import_bundle`), which enters items as DRAFT. An import never replaces a local APPROVED or REJECTED item, and adds no chain file: a bundle's chains, keys and heads are data, printed as anchors to compare with the other box. A case's signed history reaches another box only by restore, or by a copy of the case directory after close.
13. **Uninstall** removes `/var/lib/vhir`, including the ledgers and the signing keys. Close or export each case first, so its chain copies and keys are in the case. Move a case to another box only after close or export, which write the chain copies. A directory copied while the case is open carries no chain copy. Sign only in the case's original folder. A copy made by hand (outside backup and restore) can't be told apart from the original when this box has no record of where the original lives, and signing there would extend the original's signed record.
14. **Shared OS account.**
    - The installer sets up one OS account for examiners on this box, so examiners share it.
    - Anyone at its terminal, and any process running as that account, can run `--forgot-password` for any name (also as `vhir enrol --name NAME --forgot`), or enrol a name that has no credential yet.
    - The change shows as a new fingerprint, and verify warns that the key changed (limit 4). Pins (limits 1 and 4) are what detect it.
15. **What file writes can do to the result.** A file write can stop a case from reaching exit 0: for example, one signed line naming an item the case doesn't have, or a chain broken by an edit. Where the recovery verify prints is a new case, the block is permanent for this case. File writes to case and ledger data, made without your password, a signing key or a change to Valhuntir's code, can block exit 0. They can't produce an anchored exit 0 in a check run off this machine with your most recent head for every chain and your pins (limits 5, 7 and 8). With an older head, or without a chain's head, they can, because they can remove the decisions made after the head you supplied, or a whole chain copy (limit 5).
    - Without anchors, file writes can produce exit 0 (limit 1). In a case with no signed line, they can add a 0.6 record (limit 9). Removing or demoting a 0.6-only approval removes an unsigned record; it doesn't produce a signed one.
    - In a case with no signed line yet, a file write can add a record that shows as "approved under 0.6 (before signing)", and the result can be exit 0; that record carries no signature.
    - Any process can also hold the case lock. While it does, approvals wait or return `LEDGER_BUSY`. That blocks approvals; it doesn't produce one.

## Accepted Residuals

The project owner accepted these residuals on 2026-10-08:

- **Code and memory on this machine** (limit 3): the code that displays items, takes the password and signs runs on, or is served from, this machine. Any process with administrative rights, or modified code, can observe the password, use or copy the signing key while it's in use, or sign content other than what was displayed. A copied key or an observed password can sign later lines, and those lines verify VALID. Rotating the key doesn't invalidate lines signed before the rotation. This build doesn't protect against that, or detect it, while the AI keeps sudo.
- **The first line and key:** verify can't prove the case's first line and key are the originals using only this machine; comparing the key fingerprint with any earlier copy that left the machine (a backup, report or export) proves it; and a verdict is independent of this machine only when it's run off it.

## SSH Security Consideration

Remote deployments (Path 2) require SSH access to SIFT only for CLI-exclusive operations: case initialization, evidence registration, evidence unlocking, and command execution. Finding approval and rejection are available through the Examiner Portal in the browser — SSH is not required for the review workflow.

If the remote LLM client has terminal access (e.g., Claude Code), it can potentially use the examiner's SSH credentials to run commands on SIFT outside of MCP controls. Signing needs the examiner's passphrase, typed at the CLI (`/dev/tty`) or in the portal's browser; what that does and doesn't stop is in [Stated limits](#stated-limits). Other operations (file modification, evidence access) are not passphrase-gated.

For production forensic work with remote Claude Code, examiners should use SSH authentication that requires human interaction per use:

- Password-only authentication (no agent-forwarded keys)
- `ssh-add -c` for per-use agent confirmation
- Hardware security keys (FIDO2/U2F)

Alternatively, MCP-only clients (Claude Desktop, LibreChat) eliminate this concern entirely — they can only reach SIFT through audited MCP tools.

## Adversarial Evidence

Evidence under analysis may contain attacker-controlled content designed to manipulate LLM analysis. Any text field in any artifact — filenames, event log messages, registry values, email subjects, script comments, file metadata — could contain adversarial instructions.

Defenses:

- **AGENTS.md rules**: Instruct the LLM to never interpret embedded text as instructions
- **data_provenance markers**: Every tool response tags output as untrusted
- **Discipline reminders**: Rotating forensic methodology reminders in every response
- **HITL approval gate**: The primary mitigation — humans review all findings

## Evidence Handling

Never place original evidence on any Valhuntir system. Only use working copies for which verified originals or backups exist.

Any data loaded into the system runs the risk of being exposed to the underlying AI provider. Only place data on these systems that you are willing to send to your AI provider. Treat all Valhuntir systems as analysis environments, not evidence storage.

### Evidence Integrity Measures

- SHA-256 hashes computed at registration, verified on demand via `vhir evidence verify`
- Evidence registry (`evidence.json`) protected by deny rules to prevent hash tampering
- Evidence access is logged to `evidence_access.jsonl`
- `vhir evidence lock` sets the entire evidence directory to read-only (chmod 444/555)
- `vhir evidence unlock` restores write access for re-extraction

These are defense-in-depth measures. Hash-based verification is the primary integrity mechanism. Proper evidence integrity depends on verified hashes, write blockers, and chain-of-custody procedures that exist outside this platform.

### Filesystem Requirements

- **ext4**: Recommended. Full permission support for read-only protection.
- **NTFS/exFAT**: Acceptable. File permission controls will be silently ineffective.
- **FAT32**: Discouraged. 4 GB file size limit.

## Audit Trail

Every MCP tool call is logged to a per-backend JSONL file in the case `audit/` directory:

```text
audit/
├── forensic-mcp.jsonl
├── case-mcp.jsonl
├── report-mcp.jsonl
├── sift-mcp.jsonl
├── forensic-rag-mcp.jsonl
├── windows-triage-mcp.jsonl
├── opencti-mcp.jsonl
├── wintools-mcp.jsonl
└── claude-code.jsonl          # PostToolUse hook (Claude Code only)
```

Each entry includes:
- Unique evidence ID (`{backend}-{examiner}-{date}-{seq}`)
- Tool name and arguments
- Timestamp
- Examiner identity
- Case identifier

Evidence IDs resume sequence numbering across process restarts.

## Responsible Use

This project demonstrates the capabilities of AI-assisted incident response. While steps have been taken to enforce human-in-the-loop controls, it is ultimately the responsibility of each examiner to ensure that their findings are accurate and complete. Ultimate responsibility rests with the human. The AI, like a hex editor, is a tool to be used by properly trained incident response professionals. Users are responsible for ensuring their use complies with applicable laws, regulations, and organizational policies.
