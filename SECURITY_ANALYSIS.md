# Security Analysis — pi-root-grant 0.1.1

**Subject:** `pi-root-grant@0.1.1` (npm), single source file `extensions/root-grant.ts` (600 LOC).
**Source obtained from:** npm tarball (`https://registry.npmjs.org/pi-root-grant/-/pi-root-grant-0.1.1.tgz`, shasum `af0e2df16ef2cfbaa9b3b66c8f6db1f90ff0411c`).
**Reviewer:** independent code review, no execution.
**Date:** 2026-06-06.

> ⚠️ The canonical upstream git repo referenced in `package.json`
> (`github.com/OliverMarcusson/pi-root-grant`) returns **HTTP 404** — it is
> deleted or was never public. This analysis is therefore based solely on the
> published npm artifact, which cannot be diffed against git history.

---

## 1. What the extension does

A pi (coding-agent) extension that gives the agent **temporary, sudo-backed root
access** after explicit interactive user approval. It:

- Registers commands `/root`, `/root-off`, `/root-status`.
- Registers tools `request_root_access` and `revoke_root_access`.
- **Re-wraps** pi's built-in `bash`, `read`, `write`, and `edit` tools so that —
  *only while a grant is active* — their underlying operations execute through
  `sudo`.
- Prompts via `ctx.ui.confirm`, and if `sudo -n -v` fails, prompts for a masked
  sudo password.
- Auto-revokes on timer expiry and on `session_shutdown`, and runs `sudo -k`.

Privilege flow:

```
agent calls request_root_access(reason, duration)
        │
        ▼
ctx.ui.confirm("Enable root access?")  ── user denies ──► no grant
        │ user approves
        ▼
sudo -n -v succeeds? ── yes ──► grant with no stored password (NOPASSWD/cached)
        │ no
        ▼
prompt masked password ─► sudo -S -v validates ─► store password in memory
        │
        ▼
grant = { expiresAt, password }     (timer set, max 15 min)
        │
        ▼
while active: bash/read/write/edit silently run via `sudo -S` for the whole window
```

---

## 2. Controls done well

| # | Control | Where |
|---|---------|-------|
| G1 | Interactive `confirm()` is required before any grant | `enableRoot` |
| G2 | Duration is hard-capped at 15 min (`MAX_DURATION_MS`) | `parseDuration` (`Math.min`) |
| G3 | Password is masked in the TUI and sent **only** to `sudo -S` via stdin (`-p ""` suppresses the prompt) | `promptPassword`, `sudoSpawn*` |
| G4 | Auto-revoke on expiry timer **and** on `session_shutdown` | `setTimeout`, `pi.on("session_shutdown")` |
| G5 | `sudo -k` invalidates the cached sudo timestamp on revoke | `revoke` |
| G6 | Root read/write/edit refuse to operate on **symlinks** | `sudoCheckNotSymlink`, `sudoRawRead`, `sudoWrite` |
| G7 | `request_root_access` and `/root` refuse to run without an interactive UI (`ctx.hasUI`) | tool/command handlers |
| G8 | Paths/cwd in the root bash op are `shellQuote`d | `createRootBashOperations`, `shellQuote` |
| G9 | Write goes through a `0700` `mkdtemp` temp dir, then `cp` as root (no shell-expanded redirection) | `sudoWrite`, `createRootWriteOperations` |

This is a thoughtfully built extension. The findings below are about residual
risk inherent to the feature plus a few concrete weaknesses.

---

## 3. Findings

| ID | Severity | Title |
|----|----------|-------|
| F1 | **High** | A "temporary" grant lets root make itself **permanent** |
| F2 | **High** | One approval = blanket root for the whole window; no per-action gate |
| F3 | **Medium** | TOCTOU race between symlink check and file operation |
| F4 | **Medium** | In-flight root processes are **not** killed at expiry |
| F5 | **Medium** | Plaintext sudo password lingers in process memory (no real scrub) |
| F6 | **Medium** | Attacker/agent-controlled `reason`/`duration` rendered to TUI (social-engineering + possible escape-sequence injection) |
| F7 | **Medium** | Supply-chain trust: deleted upstream repo, single npm maintainer, self-updating capability |
| F8 | **Low** | `bash -lc` runs a login shell as root for every read/write |
| F9 | **Low** | No persistent audit log of root actions |
| F10 | **Low** | Dead/confused `capped` computation (correctness, not security) |

---

### F1 — "Temporary" grant ≠ temporary privilege (High)

The headline guarantee is that root is *temporary* (≤15 min, auto-revoked). But
during the window the agent has a full root shell (`createRootBashOperations`
runs arbitrary `bash -lc "... && <command>"` as root). Root can trivially
**persist** itself beyond the window:

- append a `NOPASSWD: ALL` line to `/etc/sudoers.d/`,
- add an SSH key to `/root/.ssh/authorized_keys`,
- install a launchd/cron/systemd unit,
- replace a setuid binary.

After that, the 15-min cap and `sudo -k` are meaningless — privilege survives
the grant. So the extension's security model bounds the *window of intent*, not
the *window of privilege*. Any compromise of the agent (or a successful prompt
injection) during a single approved window is effectively a full, persistent
host compromise.

**Mitigation:** treat any grant as equivalent to handing over the root password.
Only approve for trusted tasks; afterward, audit `/etc/sudoers.d`, root cron,
launchd, and `authorized_keys`. The extension cannot technically prevent this.

---

### F2 — One approval authorizes the entire window (High)

After the single `confirm()`, **every** `bash`/`read`/`write`/`edit` call runs as
root with the cached password, silently, with no further prompt until expiry
(`isActive(grant)` is the only gate). There is no per-command confirmation, no
command allow-list, no path restriction. The user approves a *reason string*,
not the actual operations that follow.

**Mitigation:** request the shortest viable duration; prefer `revoke_root_access`
immediately after the single privileged step instead of letting the timer run.

---

### F3 — TOCTOU between symlink check and operation (Medium)

`sudoCheckNotSymlink` runs `sudo test -L path` as **one** process; the actual
`cat`/`cp` runs as a **separate** sudo process afterward (`sudoRawRead`,
`createRootWriteOperations.writeFile`). The check and use are not atomic. A local
attacker (or a racing process) who can control `path`'s parent directory can pass
the `test -L` check, then swap `path` for a symlink to e.g. `/etc/sudoers` before
the `cp`, causing a root write to follow the symlink. Same pattern for read.

**Mitigation:** operate on `O_NOFOLLOW`-style primitives or `realpath`-pin +
`cp --no-dereference`/`install`, ideally in a single privileged process that both
checks and acts. As written, the symlink guard is bypassable under a race.

---

### F4 — Expiry does not terminate in-flight root processes (Medium)

Expiry is enforced two ways: a `setTimeout` that calls `revoke` (which runs
`sudo -k`), and a lazy `expireIfNeeded` checked on the *next* tool call. Neither
kills a **currently running** root child. A long-running root command started
while active (e.g. `bash` running a multi-minute job, or a backgrounded process)
keeps executing as root well past `expiresAt`; `sudo -k` only clears the cached
timestamp, it does not signal already-authenticated children. The "auto-revoke"
is thus advisory for in-flight work.

**Mitigation:** track spawned root children and `SIGKILL` them on `revoke`.

---

### F5 — Sudo password lingers in memory (Medium)

On a password-protected host the plaintext password is stored in
`grant.password` for the whole window and captured into per-call operation
closures (`createRootBashOperations(grant.password)` etc.). `revoke` does
`grant.password = ""`, but JavaScript strings are **immutable** — assigning `""`
does not overwrite the original string's backing memory. The original password
remains on the V8 heap until GC (and possibly in core dumps / swap). Closures
created before revoke also still reference the old value.

**Mitigation:** this is hard to fully solve in JS. Best effort: minimize lifetime
(short durations), avoid copying into closures, and rely on `sudo -k` + short
windows. Worth noting the password is never written to disk or logged — that part
is handled well.

---

### F6 — Untrusted text rendered to the TUI (Medium)

`reason` (and `duration`) originate from the **agent** via `request_root_access`
and are rendered verbatim in both the `confirm` dialog and the password prompt
(`promptPassword(ctx, reason)`). Two issues:

1. **Social engineering** — a compromised or injected agent can craft a benign
   sounding reason ("apply security update") to coax approval. The dialog is only
   as strong as the user's scrutiny.
2. **Terminal escape injection** — the strings are not sanitized for ANSI/control
   sequences before being placed into TUI render strings. Depending on how the
   host TUI renders them, crafted escape sequences could spoof the prompt or
   manipulate the terminal. Sanitize/strip control chars before display.

---

### F7 — Supply-chain trust (Medium)

- Installed via `pi install npm:pi-root-grant`; the npm account
  (`faithless <me@faithless.se>`, author "Oliver Marcusson") controls all future
  versions. A future release ships with the **same root-granting capability** —
  a malicious or compromised update is high-impact by design.
- The upstream GitHub repo is **404** (deleted/never public), so you cannot audit
  canonical git history or verify the npm artifact against source. Only the
  published tarball is reviewable.
- `peerDependencies` pin `@earendil-works/pi-coding-agent: "*"` and
  `typebox: "*"` — unpinned.

**Mitigation:** pin the exact version, vendor the reviewed source (as this fork
does), and re-review any upgrade. Do not enable auto-update for a sudo-capable
extension.

---

### F8 — Login shell as root for file ops (Low)

Root reads/writes use `bash -lc "cat -- \"$1\""` / `head -c`. The `-l` flag makes
it a **login** shell that sources `/etc/profile`, `/root/.bash_profile`, etc. as
root on every file read/write. That is unnecessary attack surface and makes
behavior depend on root's shell startup files. A plain `cat`/`head` (no shell, or
`bash -c` without `-l`) would be safer and faster.

---

### F9 — No persistent audit trail (Low)

Root actions produce only ephemeral UI notifications. There is no append-only log
of what commands/files were executed/modified as root, which hampers incident
forensics after a grant window.

**Mitigation:** log granted windows and root operations to a file for review.

---

### F10 — Confused `capped` flag (Low, correctness)

```ts
const capped = durationMs === MAX_DURATION_MS && parseDuration(durationText)! >= MAX_DURATION_MS;
```

`parseDuration` already clamps via `Math.min(..., MAX_DURATION_MS)`, so the second
clause re-parses the same input redundantly. Harmless but dead-ish logic; the
"(max)" label may also show for an input that exactly equals 15m without being
clamped. Cosmetic.

---

## 4. Verdict

`pi-root-grant` is a **competently engineered** extension with the right
defensive instincts: explicit consent, capped duration, masked password handling,
symlink refusal, auto-revoke, and `sudo -k`. The author clearly thought about
abuse.

However, the feature is **inherently dangerous**: it grants an autonomous agent a
full, unconstrained root shell for a time window. The two High findings (F1, F2)
are structural, not bugs — *temporary intent does not bound privilege*, and *one
approval authorizes everything*. The Medium findings (TOCTOU symlink race,
in-flight processes surviving expiry, in-memory password residue, untrusted TUI
text, supply-chain) are real and partly fixable.

**Recommendation:**

- Acceptable for **trusted, single-step, short-duration** privileged tasks on a
  personal machine, where you watch the approval and revoke immediately after.
- **Not** appropriate for unattended/autonomous agents, shared/production hosts,
  or any environment where prompt injection or a malicious update would be
  catastrophic.
- Pin the version, vendor the source (done here), disable auto-update, and audit
  persistence mechanisms after any grant window.

---

*Reviewed against the npm 0.1.1 tarball only; no dynamic testing was performed.
Findings are based on static reading of `extensions/root-grant.ts`.*
