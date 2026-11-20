import unittest
from pathlib import Path

import yaml


class TLSManifestCommandsTest(unittest.TestCase):
    def test_apply_reads_manifest_from_stdin(self):
        tasks_file = Path(__file__).resolve().parents[1] / "roles/tls/tasks/main.yml"
        tasks = yaml.safe_load(tasks_file.read_text())
        expected = {
            "Apply the demo namespace manifest": "{{ demo_namespace_manifest.stdout }}",
            "Apply the demo TLS secret": "{{ demo_tls_secret_manifest.stdout }}",
        }
        for name, stdin in expected.items():
            with self.subTest(task=name):
                command = next(task["ansible.builtin.command"] for task in tasks if task["name"] == name)
                self.assertEqual(command["argv"], ["/usr/local/bin/k3s", "kubectl", "apply", "-f", "-"])
                self.assertEqual(command["stdin"], stdin)


if __name__ == "__main__":
    unittest.main()