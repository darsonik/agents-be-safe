import unittest

from app.config import Settings
from app.providers.fireworks import FireworksClient
from app.providers.jev import JevClient


class SettingsTests(unittest.TestCase):
    def test_defaults_do_not_enable_unconfigured_providers(self):
        settings = Settings.from_env({})
        self.assertEqual(settings.port, 8000)
        self.assertEqual(settings.typesafe_model, "jev-latest")
        self.assertEqual(settings.provider_status, {"fireworks": False, "jev": False})

    def test_settings_and_clients_do_not_reveal_credentials_in_repr(self):
        settings = Settings.from_env(
            {
                "FIREWORKS_API_KEY": "secret-fireworks",
                "FIREWORKS_MODEL": "test-model",
                "TYPESAFE_API_KEY": "secret-jev",
                "GITHUB_TOKEN": "secret-github",
            }
        )
        for obj in [settings, FireworksClient("secret-fireworks", "test"), JevClient("secret-jev")]:
            self.assertNotIn("secret-", repr(obj))
        self.assertEqual(settings.provider_status, {"fireworks": True, "jev": True})

    def test_invalid_ports_fail_at_startup(self):
        for value in ["-1", "0", "65536", "invalid"]:
            with self.subTest(port=value), self.assertRaises(ValueError):
                Settings.from_env({"PORT": value})
