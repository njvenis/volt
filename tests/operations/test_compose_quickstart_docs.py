from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ComposeQuickstartDocumentationTests(unittest.TestCase):
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
        self.assertIn("--okta-publisher-config ./okta-publisher.json", readme)
        self.assertIn("--validate-only", readme)
        self.assertIn("--status", readme)


if __name__ == "__main__":
    unittest.main()
