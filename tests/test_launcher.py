"""The launcher replaces one server child at a time after a UI restart."""

import os
import unittest
from unittest.mock import Mock, patch

import run
import config


class TestLauncher(unittest.TestCase):
    def test_restart_relaunches_with_saved_settings_instead_of_live_override(self):
        first = Mock()
        first.wait.return_value = config.RESTART_EXIT_CODE
        second = Mock()
        second.wait.return_value = 0
        with patch.dict(os.environ, {"NETGUARD_MODE": "LIVE"}), \
             patch("run.subprocess.Popen", side_effect=[first, second]) as spawn:
            self.assertEqual(run.run_supervised(), 0)

        self.assertEqual(spawn.call_count, 2)
        self.assertEqual(spawn.call_args_list[0].kwargs["env"]["NETGUARD_MODE"], "LIVE")
        self.assertNotIn("NETGUARD_MODE", spawn.call_args_list[1].kwargs["env"])
        self.assertEqual(spawn.call_args_list[1].kwargs["env"]["NETGUARD_SUPERVISED"], "1")


if __name__ == "__main__":
    unittest.main()
