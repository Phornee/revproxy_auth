""" unittesting """
import unittest
from pathlib import Path

from revproxy_auth import RevProxyAuth


class Testing(unittest.TestCase):
    """ Unit testing class
    """
    def setUp(self):
        test_config_path = f'{Path(__file__).parent}/data/config.yml'
        self.revproxy_auth = RevProxyAuth(template_config_path=test_config_path)

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
        self.__class__.fresh_cookie_name = next(iter(response.created_local_cookies))
        self.assertEqual(response.status, 200)
        # Chech that it is indeed the popup
        self.assertTrue(response.content.startswith('<!--authproxy-->'))

    def test_0001_w3_auth(self):
        """ Test redirection to external site, being previously authorized
            We simulate the authorization by using the freshly created cookie from the previous test
        """
        mock_request = {'host': 'w3test.fakedomain.com',
                        'method': 'GET',
                        'endpoint': 'MarkUp/Test/HTML401/current/tests/5_3_1-BF-01.html',
                        'headers': {},
                        'params': '',
                        'data': {},
                        'cookies': {'token':self.__class__.fresh_cookie_name},
                        'form': {}}

        # Get response: as we are not authorized we should get the html of the sign in popup
        response = self.revproxy_auth._path_redirect(mock_request) # pylint: disable=protected-access
        self.assertEqual(response.status, 200)
        # Chech that it is indeed the result
        test_result_path = f'{Path(__file__).parent}/data/test_result'
        with open(test_result_path, 'r', encoding="utf8") as test_file:
            ref_lines = test_file.read().splitlines()

        resp_lines = response.content.splitlines()
        self.assertTrue(ref_lines == resp_lines)

if __name__ == '__main__':
    unittest.main()
