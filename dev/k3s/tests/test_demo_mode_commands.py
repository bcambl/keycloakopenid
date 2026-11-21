import unittest
from pathlib import Path

import yaml


class DemoModeCommandsTest(unittest.TestCase):
    def test_obsolete_shared_resources_are_pruned(self):
        tasks_file = Path(__file__).resolve().parents[1] / "roles/demo_mode/tasks/main.yml"
        tasks = yaml.safe_load(tasks_file.read_text())
        task = next((task for task in tasks if task["name"] == "Remove obsolete shared routing resources"), None)
        self.assertIsNotNone(task)
        self.assertEqual(
            task["ansible.builtin.command"]["argv"],
            [
                "/usr/local/bin/k3s",
                "kubectl",
                "delete",
                "middlewares.traefik.io/shared-auth",
                "ingressroutes.traefik.io/helloworld-shared-auth",
                "ingressroutes.traefik.io/helloworld-shared-internal",
                "--namespace={{ demo_namespace }}",
                "--ignore-not-found",
            ],
        )


if __name__ == "__main__":
    unittest.main()
