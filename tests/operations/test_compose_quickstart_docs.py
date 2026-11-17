from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ComposeQuickstartDocumentationTests(unittest.TestCase):
    def test_rc3_is_primary_arch_specific_evaluation_with_permanent_release_links(self):
        readme = (ROOT / "README.md").read_text()
        install = (ROOT / "docs/installation.md").read_text()
        self.assertIn("Primary installation: VOLT 0.1.0-rc.3 Compose evaluation release", readme)
        self.assertIn("linux/arm64", readme)
        self.assertIn("linux/amd64", readme)
        self.assertIn("optional Okta evaluation setup", readme)
        self.assertIn("https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.3", readme)
        self.assertLess(install.index("## RC3 Compose installation"),
            install.index("## RC2 Compose installation"))
        for asset in ("volt-0.1.0-rc.3-linux-arm64.tar.gz",
                      "volt-0.1.0-rc.3-linux-amd64.tar.gz",
                      "volt-compose.tar.gz", "volt-compose.tar.gz.sha256",
                      "VERIFY-RELEASE.md"):
            self.assertIn(asset, install)
        rc3 = install.split("## RC3 Compose installation", 1)[1].split(
            "## RC2 Compose installation", 1)[0]
        self.assertLess(rc3.index("Authenticate `VERIFY-RELEASE.md`"),
            rc3.index("tar -xOf \"$VOLT_ARCHIVE\" volt-compose.tar.gz"))
        self.assertIn("Do not trust a verifier, checksum, signature key or Sigstore root solely because it was included", rc3)
        self.assertIn("does not require a VOLT checkout, Git, Node.js, npm", rc3)
        self.assertIn("Group removal revokes existing sessions", rc3)

    def test_documentation_index_marks_rc3_current_and_rc2_historical(self):
        index = (ROOT / "docs/README.md").read_text()
        self.assertIn("RC3 is the current Compose evaluation prerelease", index)
        self.assertIn("[RC3 Compose evaluation installation]", index)
        self.assertIn("Historical RC2 Compose installation", index)
        self.assertNotIn("RC2 is the current Compose-compatible evaluation release", index)

    def test_rc3_password_admin_sequence_and_historical_release_identity(self):
        install = (ROOT / "docs/installation.md").read_text()
        rc3 = install.split("### Install the local password-admin demo", 1)[1].split(
            "### Optional Okta OIDC evaluation", 1)[0]
        start = rc3.index('python3 setup.py start "$HOME/.local/share/volt/demo"')
        link = rc3.index('python3 setup.py link-admin "$HOME/.local/share/volt/demo"', start)
        browser = rc3.index("choose **Sign in**", link)
        authority = rc3.index('python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"', browser)
        cleanup = rc3.index("--remove-data --confirm-project volt-demo", authority)
        self.assertLess(start, link)
        self.assertLess(link, browser)
        self.assertLess(browser, authority)
        self.assertLess(authority, cleanup)
        self.assertIn("without echoing it", rc3)
        self.assertIn("does not accept the password in a command argument or environment variable", rc3)
        self.assertIn("at least 16 characters", rc3)
        self.assertIn("sha256:a7130e38b88b781d93d84c4ddd022ba45716a06b89949a2923e1dd531db2eac1", install)
        self.assertIn("90f48211e65c9ae0556419dc7f8329170386287c", install)
        self.assertIn("0af679d77754060f2f89368830a92ddb6e3f2122", install)
        self.assertIn("volt-0.1.0-rc.2-linux-amd64.tar.gz", install)

    def test_local_demo_quickstart_creates_password_account_before_start_and_links_before_login(self):
        readme = (ROOT / "deploy/compose/README.md").read_text()
        init = readme.index("python3 setup.py init", readme.index("### macOS/Linux local demo"))
        username = readme.index("--demo-admin-username local-testing-admin", init)
        prompt = readme.index("hidden terminal prompts", readme.index("### macOS/Linux local demo"))
        start = readme.index('python3 setup.py start "$HOME/.local/share/volt/demo"', init)
        link = readme.index('python3 setup.py link-admin "$HOME/.local/share/volt/demo"', start)
        browser = readme.index("Now open `http://127.0.0.1:8180/`", link)
        authority = readme.index('python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"', browser)
        self.assertLess(prompt, init)
        self.assertLess(init, username)
        self.assertLess(username, start)
        self.assertLess(start, link)
        self.assertLess(link, browser)
        self.assertLess(browser, authority)
        self.assertIn("Python 3.11 or newer", readme)
        self.assertIn("OpenSSL command-line tools", readme)
        self.assertIn("--demo-subject local-testing-admin-subject", readme)

    def test_okta_steps_separate_login_issuer_and_api_issuer_and_require_explicit_maps(self):
        readme = (ROOT / "deploy/compose/README.md").read_text()
        self.assertIn("okta.apps.read", readme)
        self.assertIn("okta.users.read", readme)
        self.assertIn("okta.groups.read", readme)
        self.assertIn("subject_by_user_id", readme)
        self.assertIn("Do not map by email or display name", readme)
        self.assertIn("Management API issuer `https://<org>/oauth2/v1`", readme)
        self.assertIn("unencrypted RSA private PEM key of at least 2048 bits", readme)
        self.assertIn("RS256 assertions", readme)
        self.assertIn("--okta-publisher-config ./okta-publisher.json", readme)
        self.assertIn("--validate-only", readme)
        self.assertIn("--status", readme)


if __name__ == "__main__":
    unittest.main()
