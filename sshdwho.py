#!/usr/bin/env python3
"""sshdwho - effective sshd_config resolver.

For every effective sshd setting, which file:line's directive decided it,
and why. Hybrid design (sshwho precedent):

  1. Resolution authority: the real `sshd` binary. `sshd -T [-C ...] -f FILE`
     (extended test mode: checks the config, prints the effective config,
     exits -- never starts the daemon, never binds/listens) supplies the
     effective values.
  2. Static attribution: this tool parses the config chain itself (-f file,
     Include chains), applies sshd's precedence model (verified empirically
     2026-10-23 against OpenSSH 9.6p1), and cross-checks every attribution
     against `sshd -T` output -- disagreement is a fail-closed finding.

Exit codes: 0 clean | 1 findings | 2 usage / sshd missing / sshd error /
model disagreement.
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

VERSION = "1.0.0"

# Accumulating keywords: every occurrence contributes, in order [observed
# OpenSSH 9.6p1, 2026-10-23]. Surprises verified then: Port accumulates;
# AuthorizedKeysFile, PermitOpen, PermitListen, SetEnv do NOT (first wins).
ACCUMULATING = frozenset({
    "port", "listenaddress", "hostkey", "allowusers", "allowgroups",
    "denyusers", "denygroups", "acceptenv", "subsystem",
})

# The accumulating set is a hint, not load-bearing truth: the agreement
# cross-check against `sshd -T` catches misclassification (H4).
ACCUMULATING_HINT_NOTE = "[observed-openssh-9.6p1]"

# Keywords whose multi-token directive values sshd reports as ONE -T line
# per token [observed OpenSSH 9.6p1, 2026-10-23]: `AcceptEnv LANG LC_*`
# becomes `acceptenv LANG` + `acceptenv LC_*`. Expanded at parse time so
# each token attributes to the same file:line.
SPLIT_TOKENS = frozenset({
    "acceptenv", "allowusers", "denyusers", "allowgroups", "denygroups",
})


def has_explicit_port(token):
    """Best-effort [observed-approximate]: does a ListenAddress token carry
    its own port? `[::]:2022` and `host:2222` do; bare addresses don't."""
    if token.startswith("["):
        return re.search(r"\]:\d+$", token) is not None
    return re.search(r":\d+$", token) is not None


def expand_listen_values(directives, ports):
    """ListenAddress modeling [observed 9.6p1]: a bare address expands to
    one -T line per effective port; a token with an explicit port stands
    alone. ports = effective port values in order (["22"] when unconfigured)."""
    out = []
    for d in directives:
        for tok in d.value.split():
            if has_explicit_port(tok):
                out.append((tok, d))
            else:
                out.extend((f"{tok}:{p}", d) for p in ports)
    return out


class ConfigError(Exception):
    """Fail-closed: sshd missing, sshd -T error, or model disagreement."""


class MatchBlock:
    def __init__(self, index, criteria, path, line):
        self.index = index
        self.criteria = criteria
        self.path = path
        self.line = line

    def where(self):
        return f"{self.path}:{self.line}"


class Directive:
    __slots__ = ("keyword", "value", "path", "line", "match")

    def __init__(self, keyword, value, path, line, match):
        self.keyword = keyword      # lowercased
        self.value = value          # normalized (unquoted)
        self.path = path
        self.line = line
        self.match = match          # MatchBlock or None

    def where(self):
        return f"{self.path}:{self.line}"


def strip_comment(line):
    """Strip a trailing # comment (only when # is unquoted and starts the
    line or follows whitespace)."""
    out = []
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and (
                i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out)


def norm_value(keyword, value):
    """Normalize a parsed value the way `sshd -T` reports it: outer quotes
    stripped, keyword lowercased, subsystem's trailing-space padding
    stripped."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    if keyword == "subsystem":
        v = v.rstrip(" ")
    return v


def parse_file(path, directives, coverage, seen, blocks, match=None):
    apath = os.path.abspath(path)
    if apath in seen:
        return  # include-loop guard
    seen.add(apath)
    coverage.append(apath)
    try:
        with open(apath, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {apath}: {exc}")
    cur_match = match
    for lineno, raw in enumerate(lines, 1):
        text = strip_comment(raw).strip()
        if not text:
            continue
        parts = text.split(None, 1)
        kw = parts[0].lower()
        val = parts[1] if len(parts) > 1 else ""
        if kw == "match":
            cur_match = MatchBlock(len(blocks), val, apath, lineno)
            blocks.append(cur_match)
        elif kw == "include":
            for pat in val.split():
                # sshd resolves relative Include patterns against the
                # process working directory.
                for hit in sorted(glob.glob(pat)):
                    parse_file(hit, directives, coverage, seen, blocks,
                               cur_match)
        else:
            base = Directive(kw, norm_value(kw, val), apath,
                             lineno, cur_match)
            if kw in SPLIT_TOKENS:
                # One -T line per token [observed]; each token attributes
                # to the same file:line.
                for tok in base.value.split():
                    directives.append(Directive(kw, tok, apath, lineno,
                                                cur_match))
            else:
                directives.append(base)


def parse_config(path):
    directives, coverage, blocks = [], [], []
    parse_file(path, directives, coverage, set(), blocks)
    return directives, coverage, blocks


def find_sshd():
    found = shutil.which("sshd")
    if found:
        return found
    # Hermetic-test escape hatch: point at an extracted sshd binary.
    alt = os.environ.get("SSHDWHO_TEST_SSHD")
    if alt and os.path.isfile(alt) and os.access(alt, os.X_OK):
        return alt
    return None


def run_sshd_t(sshd, config, c_args):
    """Run `sshd -T` (the ONLY sshd invocation this tool ever makes -- H3).
    Returns (stdout_text, tempkey_path_or_None)."""
    base = [sshd, "-T", "-f", config]
    if c_args:
        base += ["-C", c_args]
    try:
        res = subprocess.run(base, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise ConfigError(f"sshd binary not found at {sshd}")
    tempkey = None
    if res.returncode != 0 and "no hostkeys available" in res.stderr:
        # H1: sshd -T needs a host key; retry once with an ephemeral one.
        # Its value is excluded from attribution and named as tool-injected.
        tmpdir = tempfile.mkdtemp(prefix="sshdwho-")
        tempkey = os.path.join(tmpdir, "ephemeral_host_key")
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            raise ConfigError(
                "sshd -T needs a host key but the config names none, and "
                "ssh-keygen is not available to mint an ephemeral one")
        subprocess.run([keygen, "-t", "ed25519", "-N", "", "-f", tempkey,
                        "-q"], check=True, timeout=30)
        os.chmod(tempkey, 0o600)
        res = subprocess.run(base + ["-o", f"HostKey={tempkey}"],
                             capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        low = res.stderr.lower()
        if "privilege separation user" in low:
            raise ConfigError(
                "sshd -T failed: privilege separation user 'sshd' does not "
                "exist -- install the openssh-server package (or create the "
                "sshd user) and retry")
        raise ConfigError(
            f"sshd -T failed (exit {res.returncode}):\n{res.stderr.strip()}")
    return res.stdout, tempkey


def parse_t_output(text):
    eff = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        kw, _, rest = line.partition(" ")
        kw = kw.lower()
        eff.setdefault(kw, []).append(norm_value(kw, rest))
    return eff


def find_block_concat(block_vals, reported):
    """Find, in block file order, a subsequence of match blocks whose
    concatenated values equal `reported`. Returns a list of
    (MatchBlock, value) or None. Used for accumulating keywords, where a
    matching block's values REPLACE the global ones [observed 2026-10-23]."""
    n, m = len(block_vals), len(reported)

    def rec(bi, ri):
        if ri == m:
            return []
        if bi == n:
            return None
        hit = rec(bi + 1, ri)  # block did not match sshd's criteria
        if hit is not None:
            return hit
        vals = block_vals[bi][1]
        if vals and reported[ri:ri + len(vals)] == vals:
            hit = rec(bi + 1, ri + len(vals))
            if hit is not None:
                return [(block_vals[bi][0], v) for v in vals] + hit
        return None

    return rec(0, 0)


def attribute(directives, eff, tempkey):
    """Attribute every effective value to file:line provenance, cross-
    checked against sshd -T. Raises ConfigError (S03) on disagreement."""
    by_kw = {}
    for d in directives:
        by_kw.setdefault(d.keyword, []).append(d)

    rows = []      # (keyword, [values], [provenance dicts])
    findings = []  # (rule, severity, message)

    # Effective ports for ListenAddress expansion [observed]: bare addresses
    # expand to one -T line per effective port. (Port is not allowed in
    # Match blocks, so ports are always global.)
    port_ds = [d for d in directives
               if d.keyword == "port" and d.match is None]
    ports = [d.value for d in port_ds] or ["22"]

    for kw, reported in eff.items():
        # H1: exclude the tool-injected ephemeral host key from attribution,
        # before anything else (it has no config provenance by definition).
        injected = []
        if kw == "hostkey" and tempkey:
            kept = []
            for v in reported:
                if os.path.abspath(v) == os.path.abspath(tempkey):
                    injected.append(v)
                else:
                    kept.append(v)
            reported = kept

        ds = by_kw.get(kw, [])
        if not ds:
            if injected:
                provs = [{"kind": "injected", "value": v,
                          "note": "tool-injected ephemeral host key "
                                  "(H1 fallback; no hostkey in config)"}
                         for v in injected]
                rows.append((kw, list(injected), provs))
            else:
                rows.append((kw, reported,
                             [{"kind": "default",
                               "note": "sshd default (compiled/vendor)"}]))
            continue

        glob_ds = [d for d in ds if d.match is None]
        match_ds = [d for d in ds if d.match is not None]

        if kw in ACCUMULATING:
            provs, note = attribute_accum(kw, glob_ds, match_ds, reported,
                                          findings, ports)
        else:
            if len(reported) != 1:
                raise ConfigError(
                    f"S03 model disagreement: sshd reported {len(reported)} "
                    f"values for non-accumulating keyword '{kw}' "
                    f"{ACCUMULATING_HINT_NOTE}")
            provs, note = attribute_single(kw, glob_ds, match_ds,
                                           reported[0], findings)
        for v in injected:
            provs.append({"kind": "injected", "value": v,
                          "note": "tool-injected ephemeral host key "
                                  "(H1 fallback)"})
        rows.append((kw, reported + injected, provs))
        if note:
            findings.append(note)

    return rows, findings


def attribute_single(kw, glob_ds, match_ds, reported, findings):
    """First-obtained-wins attribution for one effective value."""
    if glob_ds and glob_ds[0].value == reported:
        d = glob_ds[0]
        prov = [{"kind": "config", "file": d.path, "line": d.line,
                 "value": d.value}]
        note = None
        if len(glob_ds) > 1:
            losers = ", ".join(x.where() for x in glob_ds[1:])
            note = ("S04", "info",
                    f"shadowed directive: {d.where()} wins for '{kw}' "
                    f"(first-obtained-wins); never read: {losers}")
        return prov, note
    # The value differs from the global merge: it must come from the first
    # match block (file order) whose directive for this keyword matches
    # sshd's reported value -- sshd itself evaluated the criteria (H5).
    seen_blocks = []
    for d in match_ds:
        if d.match in seen_blocks:
            continue
        seen_blocks.append(d.match)
        if d.value == reported:
            prov = [{"kind": "config", "file": d.path, "line": d.line,
                     "value": d.value,
                     "match": {"criteria": d.match.criteria,
                               "block": d.match.where()}}]
            note = ("S05", "info",
                    f"'{kw}' = '{reported}' comes from Match block "
                    f"{d.match.where()} (criteria: '{d.match.criteria}') "
                    "[conditional -- sshd evaluated the criteria]")
            return prov, note
    raise ConfigError(
        f"S03 model disagreement: sshd reports '{kw}' = '{reported}' but no "
        f"parsed directive explains it {ACCUMULATING_HINT_NOTE}")


def attribute_accum(kw, glob_ds, match_ds, reported, findings, ports):
    """Accumulating-keyword attribution. When any matching Match block sets
    the keyword, its values REPLACE the global ones (per keyword) and the
    matching blocks' values chain in block order [observed 2026-10-23]."""
    if kw == "listenaddress":
        glob_pairs = expand_listen_values(glob_ds, ports)
    else:
        glob_pairs = [(d.value, d) for d in glob_ds]
    if [v for v, _ in glob_pairs] == reported:
        prov = [{"kind": "config", "file": d.path, "line": d.line,
                 "value": v} for v, d in glob_pairs]
        return prov, None
    # Group match directives per block, preserving file order.
    blocks, order = {}, []
    for d in match_ds:
        if d.match not in blocks:
            blocks[d.match] = []
            order.append(d.match)
        blocks[d.match].append(d)
    block_vals = []
    for b in order:
        if kw == "listenaddress":
            pairs = expand_listen_values(blocks[b], ports)
        else:
            pairs = [(d.value, d) for d in blocks[b]]
        block_vals.append((b, pairs))
    hit = find_block_concat(
        [(b, [v for v, _ in pairs]) for b, pairs in block_vals], reported)
    if hit is None:
        raise ConfigError(
            f"S03 model disagreement: sshd reports '{kw}' = {reported} but "
            f"no combination of parsed directives explains it "
            f"{ACCUMULATING_HINT_NOTE}")
    prov = []
    used = []
    pair_by_block = {b: pairs for b, pairs in block_vals}
    for blk, v in hit:
        d = next(d for v2, d in pair_by_block[blk] if v2 == v)
        prov.append({"kind": "config", "file": d.path, "line": d.line,
                     "value": v,
                     "match": {"criteria": blk.criteria,
                               "block": blk.where()}})
        if blk not in used:
            used.append(blk)
    crit = "; ".join(f"{b.where()} ('{b.criteria}')" for b in used)
    note = ("S05", "info",
            f"'{kw}' values come from matching Match block(s) {crit} "
            f"[conditional -- sshd evaluated the criteria]; global values "
            f"replaced, not merged")
    return prov, note


def render_text(config, c_args, coverage, rows, findings, default_count):
    out = []
    out.append(f"sshdwho: effective sshd config from {config}")
    if c_args:
        out.append(f"  connection context: -C {c_args}")
    out.append("  note: values resolved by `sshd -T`; -o command-line "
               "options are unseen (S08)")
    out.append("")
    out.append(f"coverage ({len(coverage)} file(s), include order):")
    for path in coverage:
        out.append(f"  {path}")
    out.append("")
    out.append("effective settings (from config files):")
    for kw, values, provs in rows:
        for v, p in zip(values, provs):
            if p["kind"] == "default":
                continue
            loc = (f"{p['file']}:{p['line']}"
                   if p["kind"] == "config" else p["note"])
            tag = ""
            if p.get("match"):
                tag = (f"  [match {p['match']['block']} "
                       f"criteria='{p['match']['criteria']}']")
            out.append(f"  {kw} = {v}\n    from: {loc}{tag}")
    out.append("")
    out.append(f"{default_count} setting(s) use sshd defaults (not in config)")
    if findings:
        out.append("")
        out.append("findings:")
        for rule, sev, msg in findings:
            out.append(f"  [{rule} {sev}] {msg}")
    return "\n".join(out)


def render_json(config, c_args, coverage, rows, findings):
    settings = []
    for kw, values, provs in rows:
        entries = []
        for v, p in zip(values, provs):
            e = {"value": v, "kind": p["kind"]}
            if p["kind"] == "config":
                e["file"], e["line"] = p["file"], p["line"]
                if p.get("match"):
                    e["match_criteria"] = p["match"]["criteria"]
                    e["match_block"] = p["match"]["block"]
            else:
                e["note"] = p["note"]
            entries.append(e)
        settings.append({"keyword": kw, "effective": entries})
    return json.dumps({
        "tool": "sshdwho", "version": VERSION,
        "config": config, "connection_context": c_args,
        "coverage": coverage,
        "banner": "effective over config files; -o options unseen (S08)",
        "settings": settings,
        "findings": [{"rule": r, "severity": s, "message": m}
                     for r, s, m in findings],
    }, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sshdwho",
        description="Effective sshd_config resolver: which file:line "
                    "decided each effective sshd setting, and why.")
    ap.add_argument("--config", default="/etc/ssh/sshd_config",
                    help="sshd config file (default: /etc/ssh/sshd_config)")
    ap.add_argument("-C", dest="c_args", metavar="CRITERIA",
                    help="connection criteria passed to `sshd -T -C`, e.g. "
                         "'user=alice,host=h,addr=1.2.3.4' (Match evaluation)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.config):
        print(f"sshdwho: config file not found: {args.config}",
              file=sys.stderr)
        return 2

    sshd = find_sshd()
    if sshd is None:  # S01
        print("sshdwho: no sshd binary found on PATH and SSHDWHO_TEST_SSHD "
              "unset -- cannot resolve effective values (no pure-static "
              "fallback; values would be model-only)", file=sys.stderr)
        return 2

    try:
        directives, coverage, _blocks = parse_config(args.config)
        stdout, tempkey = run_sshd_t(sshd, args.config, args.c_args)
        eff = parse_t_output(stdout)
        rows, findings = attribute(directives, eff, tempkey)
    except ConfigError as exc:  # S02 / S03 fail closed
        print(f"sshdwho: {exc}", file=sys.stderr)
        return 2

    default_count = sum(1 for _, _, provs in rows
                        for p in provs if p["kind"] == "default")
    shown = [(k, v, p) for k, v, p in rows
             if any(x["kind"] != "default" for x in p)]

    if args.json:
        print(render_json(args.config, args.c_args, coverage, shown,
                          findings))
    else:
        print(render_text(args.config, args.c_args, coverage, shown,
                          findings, default_count))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
