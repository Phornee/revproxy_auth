""" unittesting """
import unittest
from pathlib import Path

from http.cookies import SimpleCookie
from flask import Flask, request, Response
from bs4 import BeautifulSoup
from revproxy_auth import RevProxyAuth


class Testing(unittest.TestCase):
    """ Unit testing class
    """
    def setUp(self):
        self.app = Flask(__name__)
        self.app.add_url_rule('/', 'main', self._main_endpoint, methods=['GET', 'POST'])
        self.app.add_url_rule('/test/', 'test', self._test_endpoint, methods=['GET', 'POST'])

        self.client = self.app.test_client()
        test_config_path = f'{Path(__file__).parent}/data/config.yml'
        self.revproxy_auth = RevProxyAuth(self.app, template_config_path=test_config_path)

    def _main_endpoint(self) -> Response:
        resp = self.revproxy_auth.path_redirect("/")
        return resp

    def _test_endpoint(self) -> Response:
        return 'test response OK'

    def test_0000_w3_noauth(self):
        """ Test redirection to external site, without previously being authorized
            Response should be the content of the sign in popup itself
        """
        mock_request = {'host': 'w3test.fakedomain.com',
                        'method': 'GET',
                        'endpoint': 'MarkUp/Test/HTML401/current/tests/sec5_3_1-BF-01.html',
                        'headers': {},
                        'params': '',
                        'data': {},
                        'cookies': {},
                        'form': {}}

        # Get response: as we are not authorized we should get the html of the sign in popup
        response = self.revproxy_auth._path_redirect(mock_request) # pylint: disable=protected-access

        self.__class__.auth_cookie_name = self._get_auth_cookie_name(response)

        self.assertEqual(response.status_code, 200)
        # Chech that it is indeed the popup
        self.assertTrue(response.data.decode('utf-8').startswith('<!--authproxy-->'))

    def test_0001_w3_auth(self):
        """ Test redirection to external site, being previously authorized
            We simulate the authorization by using the freshly created cookie from the previous test
        """
        # mock_request = {'host': 'w3test.fakedomain.com',
        #                 'method': 'GET',
        #                 'endpoint': 'MarkUp/Test/HTML401/current/tests/5_3_1-BF-01.html',
        #                 'headers': {},
        #                 'params': '',
        #                 'data': {},
        #                 'cookies': {'token':self.__class__.auth_cookie_name},
        #                 'form': {}}

        mock_request = {'host': 'localhost',
                        'method': 'GET',
                        'endpoint': 'test/',
                        'headers': {},
                        'params': '',
                        'data': {},
                        'cookies': {'token':self.__class__.auth_cookie_name},
                        'form': {}}

        # Get response: as we are not authorized we should get the html of the sign in popup
        response = self.revproxy_auth._path_redirect(mock_request) # pylint: disable=protected-access
        self.assertEqual(response.status_code, 200)

        auth_cookie_name = self._get_auth_cookie_name(response)
        # We simulate the client action by sending back the right testing credentials.
        response = self.client.post('/test/', data={'user': 'pepe',
                                               'password': '123456',
                                               'OTP': '1234',
                                               'auth': auth_cookie_name})

        # Checks that it is indeed the result
        self.assertTrue(response.data.decode('utf-8') == 'test response OK')


    def _get_auth_cookie_name(self, resp: Response) -> str:
        html = resp.get_data().decode('utf-8')
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find(id='auth')['value']

    def _get_client_cookie(self, cookie_name: str) -> str:
        """ Get a incomming cookie from a http response
        Args:
            resp (Response): 
            cookie_name (str):
        Returns:
            str: Value of the coookie
        """
        cookie_value = None
        for cookie in self.client.cookie_jar:
            if cookie.name == cookie_name:
                cookie_value = cookie.value
        return cookie_value
        # cookie_value = None
        # hed = resp.headers
        # for header in hed:
        #     if header[0] == 'Set-Cookie':
        #         cookie = SimpleCookie(header[1])
        #         if cookie_name in cookie:
        #             cookie_value = cookie[cookie_name].value
        # return cookie_value

if __name__ == '__main__':
    unittest.main()
