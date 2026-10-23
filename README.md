# sshdwho

Which `sshd_config` line *actually* decided each effective sshd setting —
and why.

`sshd -T` prints the effective server configuration but never says *where*
each value came from; the usual advice is to read the config and guess.
sshdwho is a hybrid (the sshwho precedent): it asks the real `sshd` binary
(`sshd -T [-C ...] -f FILE` — extended test mode, checks the config and
exits, never starts the daemon, never binds a socket) for the effective
values, then statically parses the config chain itself (`-f` file plus
`Include` chains, in order) and cross-checks every attribution against
what sshd reported. Disagreement is a fail-closed error, never silently
papered over.

## Usage

```bash
sshdwho                                # effective config of /etc/ssh/sshd_config
sshdwho --config ./test-sshd.conf      # resolve a specific config file
sshdwho -C user=alice,host=h,addr=1.2.3.4   # evaluate Match blocks for a connection
sshdwho --json --config ./test-sshd.conf
sshdwho --version
```

Exit codes: `0` clean · `1` findings · `2` usage error / sshd missing /
sshd reported an error of its own (its stderr is surfaced verbatim) /
the static model disagrees with sshd (S03, fail closed).

## Example

```text
$ sshdwho --config ./test-sshd.conf -C user=alice,host=h,addr=1.2.3.4
sshdwho: effective sshd config from ./test-sshd.conf
  connection context: -C user=alice,host=h,addr=1.2.3.4
  note: values resolved by `sshd -T`; -o command-line options are unseen (S08)

coverage (2 file(s), include order):
  ./test-sshd.conf
  ./test-sshd.conf.d/extra.conf

effective settings (from config files):
  permitrootlogin = no
    from: ./test-sshd.conf:6  [match ./test-sshd.conf:4 criteria='User alice']
  port = 22
    from: ./test-sshd.conf:1
  port = 2222
    from: ./test-sshd.conf:2

5 setting(s) use sshd defaults (not in config)

findings:
  [S05 info] 'permitrootlogin' = 'no' comes from Match block ./test-sshd.conf:4 (criteria: 'User alice') [conditional -- sshd evaluated the criteria]
```

## What it models

Precedence rules, verified empirically 2026-10-23 against OpenSSH 9.6p1:

- **First-obtained-wins** for ordinary keywords (`PermitRootLogin yes`
  followed by `PermitRootLogin no` → `yes` — the inverse of the ssh
  *client*'s first-match-wins, and the classic footgun).
- **Accumulating keywords** — every occurrence contributes, in order:
  `port`, `listenaddress`, `hostkey`, `allowusers`, `allowgroups`,
  `denyusers`, `denygroups`, `acceptenv`, `subsystem`. Surprises: `Port`
  accumulates while `AuthorizedKeysFile`, `PermitOpen`, `PermitListen`
  and `SetEnv` do *not* (first wins).
- **Match blocks** override the global section; when several match, the
  first matching block wins per keyword. A matching block's *accumulating*
  values **replace** the global ones for that keyword (per keyword) and
  chain in block order. `Match all` is evaluated even with no `-C`.
- **Include** is processed inline, glob order.
- `sshd -T` reports one line per token for multi-token list directives
  (`AcceptEnv LANG LC_*` → two lines), strips quotes, lowercases
  keywords, and pads `subsystem` lines with a trailing space; the
  parser normalizes identically.
- **ListenAddress** without a port expands to one line per effective
  port (`0.0.0.0` → `0.0.0.0:22`, `0.0.0.0:2222`); explicit ports
  (`[::]:2022`) stand alone.

## Rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| S01 | fatal | No sshd binary found (no pure-static fallback — values would be model-only) |
| S02 | fatal | `sshd -T` failed — its stderr is surfaced verbatim (bad config, missing privsep user, …) |
| S03 | fatal | Static model disagrees with sshd's reported values — fail closed |
| S04 | info | Shadowed directive: a later first-wins line that is never read (winner + loser file:line) |
| S05 | info | Value comes from a Match block — criteria shown verbatim, tagged `[conditional]` (sshd evaluated the criteria; Group membership etc. are never guessed) |
| S06 | — | Accumulating keywords: every contributing file:line is listed in the table |
| S07 | — | Provenance `sshd default` for settings with no config directive (never upgraded to a claimed source) |
| S08 | — | Banner on every run: `-o` command-line options are an unseen layer |

## Safety

- The only sshd invocation is `sshd -T` (test-asserted); `-T` never
  binds a socket or starts the daemon.
- `sshd -T` needs a host key and the `sshd` privilege-separation user.
  If the config names no usable key, the tool retries once with an
  ephemeral `ssh-keygen` key; its value is excluded from attribution
  and named as tool-injected (H1). A missing privsep user is a named
  fatal error — the tool never creates users (H2).
- Read-only: config files are only read; paths named by directives
  (e.g. `AuthorizedKeysFile`) are never opened (H10).

## Limitations

- The accumulating-keyword list was verified on OpenSSH 9.6p1; other
  versions could differ — S03's cross-check against the real binary
  catches any drift (fail closed, not silent).
- Relative `Include` patterns resolve against the process working
  directory (sshd's behavior for `-f`).
- Match criteria the tool cannot evaluate statically (notably `Group`)
  are never guessed; attribution says "sshd reported X for these `-C`
  args; the matching block is file:line".
- ListenAddress explicit-port detection is heuristic
  (`[v6]:port` / `host:port`); S03 guards it.

## Pre-publish checklist

- [x] stdlib only, single file
- [x] tests pass (hermetic + live agreement vs real sshd 9.6p1)
- [x] README documents real behavior incl. Limitations
- [x] CHANGELOG.md present
- [x] no secrets in code/tests/history
- [x] license: MIT (pending Godsby's approval)
- [ ] Godsby's approval before first publication
