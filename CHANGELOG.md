# CHANGELOG — sshdwho

## 1.0.0 (2026-10-23)

- Initial release. Effective sshd_config resolver: `sshdwho
  [--config FILE] [-C user=,host=,addr=] [--json] [--version]`.
- Hybrid resolution: real `sshd -T` is the authority for effective values;
  static parse of the config + Include chain attributes each value to
  file:line, cross-checked (S03 fail-closed on disagreement).
- Precedence model verified empirically vs OpenSSH 9.6p1: first-obtained-wins
  scalars, nine accumulating keywords, Match-block override with
  first-matching-block-wins and per-keyword accumulator replacement,
  inline Include in glob order, `Match all` evaluated without `-C`.
- Observed -T reporting quirks modeled: one line per token for
  AcceptEnv/AllowUsers/DenyUsers/AllowGroups/DenyGroups, quote stripping,
  subsystem trailing-space padding, ListenAddress port expansion.
- Rules S01–S08; exit 0/1/2; strictly read-only (only `sshd -T` ever
  invoked; ephemeral host-key fallback named as tool-injected).
- 23 tests: hermetic parser/attribution suite + live agreement tests
  against real sshd 9.6p1 (skip-guarded via system sshd or
  SSHDWHO_TEST_SSHD). Two real bugs caught during the build (per-token
  splitting, tempkey attribution ordering).
