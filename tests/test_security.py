"""Security regressions: no credentials, email delivery or device scans required."""
import asyncio
import contextlib
import importlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sidecar'))
import auth
from alerts import resend_client
from fastapi.testclient import TestClient
from fastapi import FastAPI


class SecurityTests(unittest.TestCase):
    def setUp(self):
        auth._otp_store.clear()
        app = FastAPI()
        app.include_router(auth.router)
        self.client = TestClient(app)
        self.secret = patch.object(auth, 'JWT_SECRET', 'unit-test-only-signing-material-0000000000')
        self.secret.start()
        self.addCleanup(self.secret.stop)

    def test_unconfigured_signing_key_disables_auth_only(self):
        for key in ['', 'short', 'doxshield-default-secret-change-in-production']:
            with self.subTest(key_length=len(key)), patch.object(auth, 'JWT_SECRET', key):
                for route, body in [('send-otp', {'email': 'tester@example.invalid'}),
                                    ('verify-otp', {'email': 'tester@example.invalid', 'code': '123456'}),
                                    ('verify-token', {'token': 'invalid'})]:
                    self.assertEqual(self.client.post('/api/auth/' + route, json=body).status_code, 503)

    def test_missing_email_key_fails_without_logging_otp(self):
        with patch.dict(os.environ, {'RESEND_API_KEY': ''}), contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.client.post('/api/auth/send-otp', json={'email': 'tester@example.invalid'}).json()
        self.assertFalse(result['success'])
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(auth._otp_store, {})

    def test_provider_failure_does_not_disclose_exception_or_otp(self):
        class FailedProvider:
            class Emails:
                @staticmethod
                def send(payload):
                    raise RuntimeError('sensitive-provider-request')
        with patch.dict(os.environ, {'RESEND_API_KEY': 'not-a-real-key'}), patch.object(auth, 'resend_lib', FailedProvider), contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.client.post('/api/auth/send-otp', json={'email': 'tester@example.invalid'}).json()
        self.assertFalse(result['success'])
        self.assertNotIn('sensitive-provider-request', str(result) + output.getvalue())
        self.assertEqual(auth._otp_store, {})

    def test_successful_otp_roundtrip_and_single_use(self):
        with patch.object(auth, '_send_otp_email', return_value=(True, '')):
            self.assertTrue(self.client.post('/api/auth/send-otp', json={'email': 'tester@example.invalid'}).json()['success'])
        payload = {'email': 'tester@example.invalid', 'code': auth._otp_store['tester@example.invalid']['code']}
        result = self.client.post('/api/auth/verify-otp', json=payload).json()
        token = result['token']
        self.assertTrue(self.client.post('/api/auth/verify-token', json={'token': token}).json()['valid'])
        self.assertEqual(self.client.post('/api/auth/verify-otp', json=payload).status_code, 400)
        self.assertFalse(self.client.post('/api/auth/verify-token', json={'token': token + 'invalid'}).json()['valid'])

    def test_missing_alert_key_is_not_delivery_success(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'RESEND_API_KEY': ''}), patch.object(resend_client, 'DATA_DIR', Path(tmp)), patch.object(resend_client, 'ALERTS_FILE', Path(tmp) / 'alerts.json'):
            result = asyncio.run(resend_client.send_risk_alert('tester@example.invalid', 'Test', 'HIGH', [], 'US', [], '', []))
            self.assertFalse(result)
            self.assertTrue(resend_client.get_alert_history()[0]['skipped'])
            self.assertFalse(asyncio.run(resend_client.send_risk_alert('tester@example.invalid', 'Test', 'HIGH', [], 'US', [], '', [])))

    def test_main_import_and_health_without_credentials(self):
        # Do not enter lifespan: it would start scans on the developer's device.
        main = importlib.import_module('main')
        self.assertEqual(TestClient(main.app).get('/health').json()['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
