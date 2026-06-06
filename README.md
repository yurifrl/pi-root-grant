# pi-root-grant

> **Fork notice.** This repository is a fork. The source was obtained from the
> npm package [`pi-root-grant@0.1.1`](https://www.npmjs.com/package/pi-root-grant)
> (tarball shasum `af0e2df16ef2cfbaa9b3b66c8f6db1f90ff0411c`), originally
> authored by **Oliver Marcusson** (`me@faithless.se`) and published under the
> MIT license. The upstream git repo referenced in `package.json`
> (`github.com/OliverMarcusson/pi-root-grant`) currently returns HTTP 404, so
> this fork was seeded from the published npm artifact rather than cloned from
> git. See [`SECURITY_ANALYSIS.md`](./SECURITY_ANALYSIS.md) for an independent
> security review.

Pi package that adds an explicit, temporary root-access grant flow for agents.

## What it does

- Adds `/root`, `/root-off`, and `/root-status` commands.
- Adds `request_root_access` and `revoke_root_access` tools.
- Wraps pi's `bash`, `read`, `write`, and `edit` tools so they use `sudo` only while a grant is active.
- Prompts for confirmation and, if needed, a masked sudo password.
- Revokes access automatically on expiry and on session shutdown.

## Install

```bash
pi install npm:pi-root-grant
```

Or from git:

```bash
pi install git:github.com/OliverMarcusson/pi-root-grant
```

## Usage

Ask the agent to request root access when needed, or run:

```text
/root 5m
/root-status
/root-off
```

Durations are capped at 15 minutes.

## Security notes

Extensions run with your user permissions. This package intentionally enables sudo-backed operations only after interactive approval. Review the code before installing and grant access only for tasks you trust.
