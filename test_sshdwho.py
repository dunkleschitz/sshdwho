"""Tests for sshdwho. Hermetic parser/attribution tests plus live agreement
tests against a real sshd binary (skip-guarded: system sshd or the
SSHDWHO_TEST_SSHD escape hatch pointing at an extracted binary)."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sshdwho


class TmpCfg(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sshdwho-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def cfg(self, text, name="sshd_config"):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, 0o600)
        return path


def fake_eff(pairs):
    return {k: [sshdwho.norm_value(k, v) for v in vs]
            for k, vs in pairs.items()}


class TestParser(TmpCfg):
    def test_first_wins_attribution_and_S04(self):
        p = self.cfg("PermitRootLogin yes\nPermitRootLogin no\n")
        ds, cov, blocks = sshdwho.parse_config(p)
        self.assertEqual(len(ds), 2)
        rows, findings = sshdwho.attribute(
            ds, fake_eff({"permitrootlogin": ["yes"]}), None)
        kw, vals, provs = rows[0]
        self.assertEqual(vals, ["yes"])
        self.assertEqual(provs[0]["file"], p)
        self.assertEqual(provs[0]["line"], 1)
        self.assertTrue(any(f[0] == "S04" and "never read" in f[2]
                            for f in findings), findings)

    def test_accumulator_order(self):
        p = self.cfg("Port 22\nPort 2222\n")
        ds, _, _ = sshdwho.parse_config(p)
        rows, findings = sshdwho.attribute(
            ds, fake_eff({"port": ["22", "2222"]}), None)
        self.assertEqual([x["line"] for x in rows[0][2]], [1, 2])
        self.assertFalse(any(f[0] == "S04" for f in findings))

    def test_match_block_criteria_verbatim(self):
        p = self.cfg("Match User alice\n  PermitRootLogin no\n")
        ds, _, blocks = sshdwho.parse_config(p)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].criteria, "User alice")
        self.assertIs(ds[0].match, blocks[0])

    def test_include_glob_order_inline(self):
        os.makedirs(os.path.join(self.tmp, "d"))
        for name in ("b.conf", "a.conf"):
            with open(os.path.join(self.tmp, "d", name), "w") as fh:
                fh.write("X11Forwarding yes\n")
        p = self.cfg(f"Port 22\nInclude {self.tmp}/d/*.conf\nBanner /x\n")
        ds, cov, _ = sshdwho.parse_config(p)
        self.assertEqual(cov[1], os.path.join(self.tmp, "d", "a.conf"))
        self.assertEqual(cov[2], os.path.join(self.tmp, "d", "b.conf"))
        # inline: directives from a.conf sit between Port and Banner
        self.assertEqual([d.keyword for d in ds],
                         ["port", "x11forwarding", "x11forwarding", "banner"])

    def test_quote_strip(self):
        p = self.cfg('Banner "/tmp/my banner"\n')
        ds, _, _ = sshdwho.parse_config(p)
        self.assertEqual(ds[0].value, "/tmp/my banner")

    def test_subsystem_trailing_space(self):
        # sshd -T pads subsystem lines with a trailing space [observed]
        self.assertEqual(sshdwho.norm_value("subsystem", "sftp /x "),
                         "sftp /x")

    def test_trailing_comment(self):
        p = self.cfg("Port 22 # the ssh port\n")
        ds, _, _ = sshdwho.parse_config(p)
        self.assertEqual(ds[0].value, "22")

    def test_hash_inside_quotes_kept(self):
        p = self.cfg('Banner "a#b"\n')
        ds, _, _ = sshdwho.parse_config(p)
        self.assertEqual(ds[0].value, "a#b")

    def test_default_provenance(self):
        p = self.cfg("Port 22\n")
        ds, _, _ = sshdwho.parse_config(p)
        rows, _ = sshdwho.attribute(
            ds, fake_eff({"port": ["22"], "debianbanner": ["yes"]}), None)
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["debianbanner"][2][0]["kind"], "default")

    def test_disagreement_fail_closed(self):
        p = self.cfg("PermitRootLogin yes\n")
        ds, _, _ = sshdwho.parse_config(p)
        with self.assertRaises(sshdwho.ConfigError) as ctx:
            sshdwho.attribute(ds, fake_eff({"permitrootlogin": ["no"]}), None)
        self.assertIn("S03", str(ctx.exception))


class TestMatchAttribution(TmpCfg):
    CONF = ("PermitRootLogin yes\n"
            "AcceptEnv LANG LC_*\n"
            "Match User alice\n"
            "  PermitRootLogin no\n"
            "  AcceptEnv FOO_BAR\n")

    def test_match_single_override(self):
        p = self.cfg(self.CONF)
        ds, _, _ = sshdwho.parse_config(p)
        rows, findings = sshdwho.attribute(
            ds, fake_eff({"permitrootlogin": ["no"],
                          "acceptenv": ["FOO_BAR"]}), None)
        by_kw = {r[0]: r for r in rows}
        prov = by_kw["permitrootlogin"][2][0]
        self.assertIn("User alice", prov["match"]["criteria"])
        self.assertEqual(prov["line"], 4)
        self.assertTrue(any(f[0] == "S05" and "[conditional" in f[2]
                            for f in findings), findings)

    def test_match_accumulator_replaces_global(self):
        # [observed 2026-10-23]: matching block's AcceptEnv REPLACES the
        # global LANG LC_*, it does not append.
        p = self.cfg(self.CONF)
        ds, _, _ = sshdwho.parse_config(p)
        rows, _ = sshdwho.attribute(
            ds, fake_eff({"acceptenv": ["FOO_BAR"]}), None)
        provs = rows[0][2]
        self.assertEqual(len(provs), 1)
        self.assertEqual(provs[0]["line"], 5)
        self.assertIn("alice", provs[0]["match"]["criteria"])

    def test_match_accum_two_blocks_chain(self):
        p = self.cfg("AcceptEnv LANG\n"
                     "Match User bob\n"
                     "  AcceptEnv AAA\n"
                     "Match all\n"
                     "  AcceptEnv BBB\n")
        ds, _, _ = sshdwho.parse_config(p)
        rows, _ = sshdwho.attribute(
            ds, fake_eff({"acceptenv": ["AAA", "BBB"]}), None)
        self.assertEqual([x["line"] for x in rows[0][2]], [3, 5])

    def test_no_match_global_wins(self):
        p = self.cfg(self.CONF)
        ds, _, _ = sshdwho.parse_config(p)
        rows, findings = sshdwho.attribute(
            ds, fake_eff({"permitrootlogin": ["yes"],
                          "acceptenv": ["LANG", "LC_*"]}), None)
        by_kw = {r[0]: r for r in rows}
        self.assertIsNone(by_kw["permitrootlogin"][2][0].get("match"))
        self.assertFalse(any(f[0] == "S05" for f in findings))


def find_test_sshd():
    """Real sshd for live agreement tests, or None (skip)."""
    sshd = shutil.which("sshd") or os.environ.get("SSHDWHO_TEST_SSHD")
    if not sshd or not os.access(sshd, os.X_OK):
        return None
    # Probe: the binary must actually run -T (privsep user present).
    probe = tempfile.NamedTemporaryFile("w", suffix="_sshdwho",
                                        delete=False)
    try:
        probe.write("Port 22\n")
        probe.close()
        os.chmod(probe.name, 0o600)
        res = subprocess.run([sshd, "-T", "-f", probe.name],
                             capture_output=True, text=True, timeout=30)
        if "privilege separation user" in res.stderr.lower():
            return None
        return sshd
    finally:
        os.unlink(probe.name)


TEST_SSHD = find_test_sshd()


@unittest.skipIf(TEST_SSHD is None,
                 "no runnable sshd (need system sshd or SSHDWHO_TEST_SSHD)")
class TestLiveAgreement(TmpCfg):
    def resolve(self, config, c_args=None):
        ds, cov, _ = sshdwho.parse_config(config)
        stdout, tempkey = sshdwho.run_sshd_t(TEST_SSHD, config, c_args)
        eff = sshdwho.parse_t_output(stdout)
        rows, findings = sshdwho.attribute(ds, eff, tempkey)
        return rows, findings, tempkey

    def test_live_first_wins_and_accum(self):
        p = self.cfg("PermitRootLogin yes\nPermitRootLogin no\n"
                     "Port 22\nPort 2222\nAcceptEnv LANG LC_*\n")
        rows, findings, tempkey = self.resolve(p)
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["permitrootlogin"][1], ["yes"])
        self.assertEqual(by_kw["port"][1], ["22", "2222"])
        self.assertEqual(by_kw["acceptenv"][1], ["LANG", "LC_*"])
        # ephemeral host key named as tool-injected
        hk = by_kw["hostkey"]
        self.assertTrue(all(x["kind"] == "injected" for x in hk[2]), hk)
        self.assertTrue(any(f[0] == "S04" for f in findings))

    def test_live_match_override_with_C(self):
        p = self.cfg("PermitRootLogin yes\n"
                     "Match User alice\n"
                     "  PermitRootLogin no\n")
        rows, findings, _ = self.resolve(
            p, "user=alice,host=h,addr=1.2.3.4")
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["permitrootlogin"][1], ["no"])
        prov = by_kw["permitrootlogin"][2][0]
        self.assertIn("alice", prov["match"]["criteria"])
        self.assertTrue(any(f[0] == "S05" for f in findings))

    def test_live_match_accum_replaces_global(self):
        p = self.cfg("AcceptEnv LANG LC_*\n"
                     "Match User bob\n"
                     "  AcceptEnv FOO_BAR\n"
                     "Match all\n"
                     "  AcceptEnv BAZ_QUX\n")
        rows, _, _ = self.resolve(p, "user=bob,host=h,addr=1.2.3.4")
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["acceptenv"][1], ["FOO_BAR", "BAZ_QUX"])
        crits = [x["match"]["criteria"] for x in by_kw["acceptenv"][2]]
        self.assertEqual(crits, ["User bob", "all"])

    def test_live_match_all_without_C(self):
        p = self.cfg("AcceptEnv LANG\n"
                     "Match all\n"
                     "  AcceptEnv BAZ\n")
        rows, _, _ = self.resolve(p)
        by_kw = {r[0]: r for r in rows}
        # Match all applies even without -C [observed]; global replaced.
        self.assertEqual(by_kw["acceptenv"][1], ["BAZ"])

    def test_live_no_C_global_kept(self):
        p = self.cfg("PermitRootLogin yes\n"
                     "Match User alice\n"
                     "  PermitRootLogin no\n")
        rows, findings, _ = self.resolve(p)
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["permitrootlogin"][1], ["yes"])
        self.assertFalse(any(f[0] == "S05" for f in findings))

    def test_live_listenaddress_port_expansion(self):
        # [observed 9.6p1]: bare address x each effective port; explicit
        # port stands alone.
        p = self.cfg("Port 22\nPort 2222\n"
                     "ListenAddress 0.0.0.0\n"
                     "ListenAddress [::]:2022\n")
        rows, _, _ = self.resolve(p)
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["listenaddress"][1],
                         ["0.0.0.0:22", "0.0.0.0:2222", "[::]:2022"])
        self.assertEqual([x["line"] for x in by_kw["listenaddress"][2]],
                         [3, 3, 4])

    def test_live_multi_token_split(self):
        # [observed 9.6p1]: one -T line per token for user/group/env lists.
        p = self.cfg("AllowUsers root alice\n")
        rows, _, _ = self.resolve(p)
        by_kw = {r[0]: r for r in rows}
        self.assertEqual(by_kw["allowusers"][1], ["root", "alice"])
        self.assertEqual([x["line"] for x in by_kw["allowusers"][2]], [1, 1])


class TestNeverExecutes(TmpCfg):
    """H3: the tool's ONLY sshd invocation shape is `sshd -T ...`."""

    def test_only_sshd_T_invoked(self):
        p = self.cfg("PermitRootLogin yes\n")
        calls = []
        real_run = subprocess.run

        class FakeCompleted:
            returncode = 0
            stdout = ("permitrootlogin yes\nhostkey /tmp/k\n")
            stderr = ""

        def spy(argv, **kw):
            calls.append(list(argv))
            return FakeCompleted()

        sshdwho.subprocess.run = spy
        sshdwho.find_sshd = lambda: "/fake/sshd"
        try:
            rc = sshdwho.main(["--config", p, "--json"])
        finally:
            sshdwho.subprocess.run = real_run
            del sshdwho.find_sshd
        self.assertEqual(rc, 0)
        self.assertTrue(calls, "expected at least one subprocess call")
        for argv in calls:
            if argv[0] == "/fake/sshd":
                self.assertIn("-T", argv)
                self.assertNotIn("-d", argv)

    def test_json_shape(self):
        p = self.cfg("PermitRootLogin yes\nPermitRootLogin no\n")
        ds, cov, _ = sshdwho.parse_config(p)
        rows, findings = sshdwho.attribute(
            ds, fake_eff({"permitrootlogin": ["yes"]}), None)
        doc = json.loads(sshdwho.render_json(p, None, cov,
                                             [(r[0], r[1], r[2])
                                              for r in rows], findings))
        self.assertEqual(doc["tool"], "sshdwho")
        self.assertTrue(any(f["rule"] == "S04"
                            for f in doc["findings"]))


if __name__ == "__main__":
    unittest.main()
