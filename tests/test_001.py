""" unittesting """
import unittest
from pathlib import Path

from flask import Flask, request, Response
from bs4 import BeautifulSoup

from revproxy_auth import RevProxyAuth, get_totp_token


class Testing(unittest.TestCase):
    """ Unit testing class
    """
    def setUp(self):
        self.app = Flask(__name__)
        self.app.add_url_rule('/', 'test', self._test_endpoint, methods=['GET', 'POST'])
        self.client = self.app.test_client()
        test_config_path = f'{Path(__file__).parent}/data/config.yml'
        self.revproxy_auth = RevProxyAuth(self.app, template_config_path=test_config_path, dry_run=True)

    def _test_endpoint(self) -> Response:
        auth_resp = self.revproxy_auth.get_auth_response(request,
                                                         lambda : Response('test result OK',
                                                                           status=200,
                                                                           content_type='text/plain')
                                                        )
        return auth_resp

    def test_0000_integrated_noauth(self):
        """ Test integrated call with noauth
        """
        # Get response: as we are not authorized we should get the html of the sign in popup
        response = self.client.get('/')

        self.assertEqual(response.status_code, 200)

        # Chech that it is indeed the popup
        self.assertTrue(response.data.decode('utf-8').startswith('<!--authproxy-->'))

        self.__class__.auth_cookie_name = self._get_auth_cookie_name(response)
        self.assertIsNotNone(self.__class__.auth_cookie_name, 'Cookie name was not send by server.')

        # We loop two times, because it could be the case that the OTP calculated here in the test, just expires
        # before the internal code of revproxy_auth can check it. So, in that unlikely (but possible) case, we
        # just retry it once inmediately (before 30 seconds)
        for i in range(2):
            # Artificially adds a leading space to user, to test that it is correctly ignored
            test_user_ok = ' ' + self.revproxy_auth._config['credentials'][0]['user']
            test_pass_ok = self.revproxy_auth._config['credentials'][0]['password']
            test_otp_secret = self.revproxy_auth._config['credentials'][0]['otp_secret']

            correct_otp = get_totp_token(test_otp_secret)

            # We simulate the client action by sending back the right testing credentials.
            response = self.client.post('/', data={'user': test_user_ok,
                                                'password': test_pass_ok,
                                                'OTP': correct_otp,
                                                'revproxy_auth': self.__class__.auth_cookie_name})
            # Expected result is 302. If we have bad luck, and OTP just expired vefore revproxy checks for it,
            # then inmediatly try a second time
            if response.status_code == 302:
                break

        # We should get a redirect to the original endpoint after the authentication
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://localhost/')

        # Simulate redirection
        response = self.client.get(response.location)

        self.assertTrue(response.data.decode('utf-8').startswith('test result OK'))

    def test_0001_integrated_auth(self):
        """ Test integrated, being previously authorized
            We simulate the authorization by using the freshly created cookie from the previous test
        """
        # We were already authenticated in previous test... so we should get the result in the lambda
        # We fake the token with the auth token to try to hack the system
        self.client.set_cookie('token',  self.__class__.auth_cookie_name, domain='localhost')
        response = self.client.get('/', headers={'Content-Type': 'application/json'})

        self.assertEqual(response.status_code, 200)
        # We tried to fake session cookie, so we should get authproxy popup instead
        self.assertTrue(response.data.decode('utf-8').startswith('<!--authproxy-->'))

    def _get_auth_cookie_name(self, resp: Response) -> str:
        html = resp.get_data().decode('utf-8')
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find(id='revproxy_auth')['value']

if __name__ == '__main__':
    unittest.main()
