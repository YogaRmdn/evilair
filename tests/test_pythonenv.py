import os
import sys
import unittest
from unittest.mock import patch

from evilair.util.pythonenv import ENV_VAR, preferred_python


class PreferredPythonTests(unittest.TestCase):
    def test_environment_override_wins(self):
        with patch.dict(os.environ, {ENV_VAR: sys.executable}):
            self.assertEqual(preferred_python(), sys.executable)

    def test_invalid_override_does_not_leak(self):
        with patch.dict(os.environ, {ENV_VAR: "/definitely/not/here"}):
            self.assertNotEqual(preferred_python(), "/definitely/not/here")

    def test_returns_executable_or_none(self):
        with patch.dict(os.environ, {ENV_VAR: ""}):
            result = preferred_python()
        if result is not None:
            self.assertTrue(os.path.isfile(result))
            self.assertTrue(os.access(result, os.X_OK))


if __name__ == "__main__":
    unittest.main()
