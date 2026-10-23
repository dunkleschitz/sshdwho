# DESIGN-sshdwho.md — hazard-first design review

`sshdwho [-C user=,host=,addr=] [--config FILE]` — effective sshd_config
resolver: for every effective sshd setting, which file:line's directive
decided it, and why.
IDEA promoted Oct 23 (2 search passes: no CLI holder — `sshd -T` /
`sshd -T -C` print effective values with zero provenance; only prose
guides and recipes).

## The question and the model

"Which line actually set PasswordAuthentication?" The tool is a
**hybrid** (sshwho precedent):

1. **Resolution authority: the real `sshd` binary.** `sshd -T [-C
   user=,host=,addr=] -f FILE` (extended test mode: checks the config,
   prints the effective configuration, exits — never starts the daemon,
   never binds/listens) supplies the effective values.
2. **Static attribution: per-file parse.** The tool parses the config
   chain itself (`-f` file, `Include` chains) recording (file, line)
   per directive, applies sshd's precedence model, and cross-checks
   every attribution against `sshd -T` output — disagreement is a
   fail-closed finding, never silently papered over.

Precedence model — **verified empirically 2026-10-23 against real
OpenSSH 9.6p1** (extracted from the Ubuntu .deb; `sshd -T -f` fixtures):

- **First-obtained-wins** for ordinary keywords [observed]:
  `PermitRootLogin yes` + `PermitRootLogin no` → `yes`;
  `PasswordAuthentication yes` + `no` → `yes`; `X11Forwarding`,
  `Banner`, `AuthorizedKeysFile`, `PermitOpen`, `PermitListen`,
  `SetEnv` all first-wins. (The classic footgun vs the ssh *client*'s
  first-match-wins.)
- **Accumulating keywords** (every occurrence contributes, in order)
  [observed]: `port`, `listenaddress`, `hostkey`, `allowusers`,
  `allowgroups`, `denyusers`, `denygroups`, `acceptenv`, `subsystem`
  (per subsystem name). NOTE the surprises: `Port` accumulates (both
  ports listed), `AuthorizedKeysFile` does NOT (first wins),
  `PermitOpen`/`PermitListen` do NOT (first wins), `SetEnv` does NOT
  (first wins).
- **Match blocks override the global section** [observed]: with
  `Match User alice` → `PasswordAuthentication no`, plain `sshd -T`
  reports the global `yes`, `-C user=alice,host=h,addr=1.2.3.4`
  reports `no`. When several Match blocks match one connection, the
  **first matching block wins per keyword** [observed: `Match User
  alice` (no) beat the later `Match Address 10.0.0.0/8` (yes)].
  `Match all` is evaluated even with no `-C` args [observed].
- **Include is processed inline** at the directive's position, glob
  order [observed].
- `sshd -T` prints ~95 lines including **compiled-in/vendor defaults**
  (e.g. `debianbanner yes`) and lowercases keywords, strips quotes
  (`banner /tmp/my banner`), and pads subsystem lines with a trailing
  space [all observed] — the parser/comparator must normalize for all
  of these.

## Hazards (hazard-first)

- **H1 — `-T` needs a host key.** `sshd -T` exits(255) with "no
  hostkeys available" when the config names no usable key [observed].
  The tool first tries plain `-T`; only on that exact error it retries
  with an ephemeral `-o HostKey <tempkey>`, and any `hostkey` value
  matching the temp key is excluded from attribution and named as
  tool-injected (HostKey accumulates, so config lines still attribute
  correctly).
- **H2 — `-T` needs the privsep user.** "Privilege separation user
  sshd does not exist" → exit 255 [observed]. Fail closed with a named
  error suggesting the package install; never create users.
- **H3 — never execute/listen.** Only `sshd -T` is ever invoked
  (test-asserted: no `-d`, no daemon flags, no other subcommand —
  `sshd` has no other test mode). `-T` never binds a socket.
- **H4 — accumulator-list drift.** The accumulating set above is
  [observed] on 9.6p1; other versions could differ. The list is a
  hint, not load-bearing truth: the agreement cross-check against
  `sshd -T` catches any misclassification (fail-closed finding).
- **H5 — Match-block conditional attribution.** With `-C`, sshd
  evaluates criteria itself; statically the tool attributes the
  winning Match block's file:line and shows its criteria verbatim,
  tagged [conditional]. Criteria the tool cannot evaluate (Group
  membership, RDomain) are never guessed — the verdict stays
  "sshd reported X for these -C args; the matching block is file:line".
  Without `-C`, `Match all`-style blocks may still apply [observed] —
  the report says which Match blocks sshd evaluated.
- **H6 — `-o` CLI options are an unseen layer.** Like tfwho's CLI
  flags: if the operator runs sshd with `-o`, the tool cannot see it.
  Bannered on every run ("effective over config files; -o options
  unseen").
- **H7 — keyword case/value normalization.** `sshd -T` lowercases
  keywords and unquotes values; the static parser normalizes
  identically before comparing, and the comparator strips the
  trailing-space padding [observed].
- **H8 — defaults are not config.** ~95 output lines are mostly
  defaults. Provenance distinguishes `file:line` from `sshd default`
  (compiled/vendor/man-page — never upgraded to a claimed source).
- **H9 — config errors.** `sshd -T` exit != 0 → fail closed, stderr
  surfaced verbatim, exit 2. stderr warnings on exit 0 are tolerated
  (netplanwho precedent).
- **H10 — secrets.** sshd_config rarely holds secrets, but
  `AuthorizedKeysFile`/`RevokedKeys` *paths* are shown, never file
  contents (the tool never opens paths named by directives).

## Rules (planned)

- S01: sshd binary missing → named error, exit 2 (no pure-static
  fallback — values would be model-only).
- S02: `sshd -T` non-zero → fail closed, stderr verbatim, exit 2.
- S03: model/authority disagreement → fail closed (the honesty
  backstop).
- S04: shadowed directives (later first-wins line never read) → info
  finding with winner+loser file:line (the core debug value — the
  exact inverse of the ssh client's footgun).
- S05: Match-sourced values → info with criteria + [conditional] tag.
- S06: accumulating keywords → all contributing file:lines listed.
- S07: `sshd default` provenance for unset options.
- S08: `-o`-unseen banner on every run.

Exit codes: 0 clean · 1 findings · 2 usage / sshd missing / sshd error /
model disagreement.

## CLI shape (planned)

`sshdwho [--config FILE] [-C user=,host=,addr=] [--json] [--version]`

- `--config` defaults to `/etc/ssh/sshd_config`; `-C` passed through
  to `sshd -T` for Match evaluation (never interpreted by the tool).
- Every run prints a coverage section (files read in Include order).
- `--root-dir` is NOT offered: sshd resolves `Include` against the
  live filesystem and needs the privsep user — hermetic testing goes
  through `-f` fixture configs instead (fully supported: all parser
  and agreement tests use `-f`).

## Verification plan

Parser/merge unit tests: hermetic. Agreement tests: real extracted
`sshd -T -f` fixtures (first-wins, accumulation per keyword,
Match ± `-C`, Include order, defaults) — runnable anywhere the
openssh-server .deb can be fetched (this machine: verified working).
Skip-guarded on `shutil.which("sshd")` OR the documented
extract-and-run recipe so CI without the binary still runs the
hermetic suite.

## Build verdict

**BUILD APPROVED.** Empirical verification is now possible here (the
extracted 9.6p1 binary + privsep user + ephemeral host key recipe),
so the build can ship with live agreement tests instead of
skip-guards. The accumulator list above is the verified core; H4's
cross-check keeps it honest across versions.

## Build notes (2026-10-23, v1.0.0)

Empirical refinements found during the build (all against real 9.6p1):

- **Match-block accumulators replace, not merge:** when a matching Match
  block sets an accumulating keyword, the global values for that keyword
  are discarded (per keyword — other accumulators keep their global
  values); matching blocks' values chain in block order. E.g. global
  `AcceptEnv LANG LC_*` + matching `Match User bob` / `AcceptEnv FOO_BAR`
  → sshd reports only `acceptenv FOO_BAR`.
- **Per-token -T lines:** `AcceptEnv LANG LC_*`, `AllowUsers root alice`,
  `DenyUsers`, `AllowGroups`, `DenyGroups` report one line per token;
  the parser expands multi-token directives at parse time (same
  file:line per token).
- **ListenAddress port expansion:** a bare address expands to one line
  per effective port (`0.0.0.0` → `0.0.0.0:22`, `0.0.0.0:2222` with two
  Ports); explicit-port tokens (`[::]:2022`) stand alone. Modeled with
  the explicit-port heuristic + S03 guard.
- **`Port` is illegal inside Match** (sshd errors) → S02 fail-closed.
- Two real bugs caught by the test suite during the build: the per-token
  splitting above, and the ephemeral host-key value being attributed as
  "sshd default" when the config had no HostKey (ordering fix: H1
  exclusion now runs before the default branch).
