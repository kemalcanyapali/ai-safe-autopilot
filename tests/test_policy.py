import tempfile
import unittest
from pathlib import Path

from policy import classify_paths, secret_findings


class PathPolicyTests(unittest.TestCase):
    def test_rejects_private_and_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / ".env", root / "node_modules" / "x.js", root / "id_rsa"]
            violations, _ = classify_paths(paths)

        self.assertEqual(len(violations), 3)

    def test_allows_environment_templates(self):
        violations, review = classify_paths([Path(".env.example")])

        self.assertEqual(violations, [])
        self.assertEqual(review, [])

    def test_marks_control_plane_and_deploy_files_for_review(self):
        _, review = classify_paths(
            [Path(".github/workflows/release.yml"), Path("scripts/deploy-prod.ts")]
        )

        self.assertEqual(
            review,
            [".github/workflows/release.yml", "scripts/deploy-prod.ts"],
        )


class SecretPolicyTests(unittest.TestCase):
    def test_detects_added_credentials(self):
        findings = secret_findings(
            "diff --git a/x b/x\n+OPENAI_KEY='sk-proj-abcdefghijklmnopqrstuvwxyz123456'\n"
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("OpenAI key", findings[0])

    def test_ignores_removed_lines_and_environment_references(self):
        findings = secret_findings(
            "-password='real-value-that-was-removed'\n"
            "+password='${{ secrets.DEPLOY_PASSWORD }}'\n"
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
