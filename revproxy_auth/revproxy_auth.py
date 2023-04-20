""" Class to perform authentication using the synology authmethods """
import os
import time
from urllib import parse
import json
from pathlib import Path
import secrets
from typing import Union
import jinja2
import requests
from flask import request, Response, send_from_directory

from config_yml import Config

COOKIE_LIFE_MINUTES = 15

class ApiRestResponse():
    """ Api Rest reponse data, platform (flask) independent"""
    def __init__(self, content: str,
                 set_cookies: dict=None,
                 delete_cookies: dict=None,
                 created_local_cookies: dict=None,
                 status: int=200,
                 content_type: str='application/octet-stream') -> None:
        self.content = content
        self.set_cookies = {} if not set_cookies else set_cookies
        self.delete_cookies = {} if not delete_cookies else delete_cookies
        self.status = status
        self.content_type = content_type
        self.created_local_cookies = {} if not created_local_cookies else created_local_cookies

class RevProxyAuth():
    """ 
    Class to manage the authentication. 
    The path_redirect function should be called from a '/<path:path>' flask rule
    Also a rule '/' should call this function like this:  return self.auth_proxy.path_redirect("/")
    """
    def __init__(self, template_config_path: str=None) -> None:
        """
            template_config_path: full path of configuration template
        """

        if not template_config_path:
            template_config_path = os.path.join(Path(__file__).parent.resolve(), './config-template.yml')

        self._config = Config('authproxy', template_config_path, 'config.yml')

        self.cookie_folder = os.path.join(Path(__file__).parent.resolve(), 'cookies')

    def path_redirect(self, path) -> Response:
        """Main entry point
        Returns:
            http_response: response string
        """
        print(f'---------------------- Path requested: {path} --------------------')

        request_dict = {'host': request.host,
                        'endpoint': path,
                        'method': request.method,
                        'params': request.query_string.decode("utf-8"),
                        'data': request.get_data(),
                        'headers': request.headers,
                        'cookies': request.cookies,
                        'form': request.form
                        }

        resp = self._path_redirect(request_dict)

        if isinstance(resp, ApiRestResponse):
            flask_response = Response(resp.content, status=resp.status, content_type=resp.content_type)
            if resp.delete_cookies:
                for del_cookie, domain in resp.delete_cookies.items():
                    flask_response.delete_cookie(del_cookie, domain)
            if resp.set_cookies:
                for set_cookie, value in resp.set_cookies.items():
                    flask_response.set_cookie(set_cookie, value, max_age=COOKIE_LIFE_MINUTES*60)

            return flask_response
        else:
            return resp

    def _build_cookie(self, req_dict: dict) -> tuple:
        mapping_info = self._config['mapping'].get(req_dict['host'])
        if not mapping_info:
            return None, None

        host = mapping_info.get('host')
        endpoint = mapping_info.get('endpoint')
        method = mapping_info.get('method')
        params = req_dict['params']

        ser_head = {}
        for head in req_dict['headers']:
            ser_head[head[0]] = head[1]
        headers = json.dumps(ser_head)

        # Stores the internal URL into a cookie file to be read later
        cookie_name = secrets.token_urlsafe(16)
        content = str(req_dict['data'])
        cookie = {'host': host,
                  'endpoint': endpoint, 
                  'method': method,
                  'params': params, 
                  'headers': headers,
                  'content': content}

        return cookie, cookie_name

    def _write_cookie(self, cookie: dict, cookie_name: str):
        cookie_path = os.path.join(self.cookie_folder, cookie_name)
        with open(cookie_path, 'w', encoding="utf-8") as cookie_file:
            json.dump(cookie, cookie_file)

    def _clear_expired_cookies(self):
        for filename in os.listdir(self.cookie_folder):
            filepath = os.path.join(self.cookie_folder, filename)
            # checking if it is a file
            if os.path.isfile(filepath):
                age = time.time() - os.path.getmtime(filepath)
                if age > COOKIE_LIFE_MINUTES*60:
                    os.remove(filepath)

    def _build_auth_popup(self, cookie_name: str) -> ApiRestResponse:
        # Get the auth html form template and send back to the user, so he can authenticate
        form_path = os.path.join(Path(__file__).parent.resolve(), 'templates', 'form.html')
        with open(form_path, 'r', encoding="utf8") as form:
            buff = form.read()
            # replace the cookie name
            env = jinja2.Environment()
            template = env.from_string(buff)
            content = template.render(token=cookie_name)
            return ApiRestResponse(content, content_type='text/html')

    def _get_local_cookie(self, token:str = None):
        cookie = None
        if token:
            cookie_path = os.path.join(self.cookie_folder, token)
            if os.path.exists(cookie_path):
                with open(cookie_path, 'r', encoding="utf-8") as cookie_file:
                    cookie = json.load(cookie_file)

                    cookie['headers'] = json.loads(cookie['headers'])
        return cookie

    def _credentials_valid(self, form):
        token = form.get('token', None)
        if token:
            user = form.get('user', None)
            password = form.get('password', None)
            otp = form.get('OTP', None)
            url = (f'{self._config["NAS"]}/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login'
                   f'&account={user}&passwd={password}&otp_code={otp}')
            auth_response = requests.get(url, timeout=10)
            # Verify authentication
            return auth_response.json()['success']
        return False

    def _call_inner_get(self, host, endpoint, params, headers) -> ApiRestResponse:
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.get(fullpath,
                            params=params,
                            headers = headers,
                            timeout=10)
        return ApiRestResponse(resp.text, status=resp.status_code, content_type=resp.headers['content-type'])

    def _call_inner_post(self, host, endpoint, data, headers) -> ApiRestResponse:
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.post(fullpath,
                             data = data,
                             headers = headers,
                             timeout=10)
        return ApiRestResponse(resp.text, status=resp.status_code, content_type=resp.headers['content-type'])

    def _reask_credentials(self, request_dict: dict, old_cookie_name: str = None) -> ApiRestResponse:
        new_cookie, new_cookie_name = self._build_cookie(request_dict)
        if not new_cookie: # Unable to build cookie for requested path: host unknown
            return ApiRestResponse(request_dict['host'], status=501)
        self._clear_expired_cookies() # Housekeeping
        print(f'Creating new cookie {new_cookie_name}')
        self._write_cookie(new_cookie, new_cookie_name)
        response = self._build_auth_popup(new_cookie_name)
        response.created_local_cookies[new_cookie_name] = new_cookie
        if old_cookie_name:
            response.delete_cookies['token'] = request_dict['host']
            print(f'Deleting cookie in response: {old_cookie_name}')
            # response.delete_cookie('token', request_dict['host'])
        return response

    def _first_auth_and_redirect(self, request_dict) -> ApiRestResponse:
        cookie_name = request_dict['form'].get('token', None) if request_dict['form'].get('from_auth') else None
        cookie = self._get_local_cookie(cookie_name)
        if cookie:
            print(f'Local cookie {cookie_name} still alive')
            if self._credentials_valid(request_dict['form']):
                print('Credentials validated by synology NAS')
                # Search for the cookie and redirect to related URL if present
                if cookie['method'] == 'GET':
                    response = self._call_inner_get(cookie['host'], cookie['endpoint'], cookie['params'], {})
                else:
                    response = self._call_inner_post(cookie['host'], cookie['endpoint'], cookie['content'], {})
                response.set_cookies['token'] = cookie_name
                # response.set_cookie('token', cookie_name, max_age=COOKIE_LIFE_MINUTES*60)
            else: # We come from the auth popup, but credentials are invalid --> ask again for credentials
                print('Credentials rejected by synology NAS. Reopening auth popup')
                response = self._build_auth_popup(cookie_name)
        else: # We got a token, but its no longer valid --> ask again for credentials
            print('Local cookie expired. Reopening auth popup')
            response = self._reask_credentials(request_dict, cookie_name)
        return response


    def _path_redirect(self, request_dict) -> Union[ApiRestResponse, Response]:
        """ Flask independent internal function
        Returns:
            http_response: response string
        """
        if request_dict['endpoint'] == 'favicon.ico':
            cookie, cookie_name = self._build_cookie(request_dict)
            print(f"favicon.ico requested: Directly returning from inner endpoint {cookie['host']}")
            return self._call_inner_get(host=cookie['host'],
                                        endpoint=request_dict['endpoint'],
                                        params=request_dict['params'],
                                        headers=request_dict['headers'])

        if request_dict['endpoint'].startswith('revproxy_auth_static'):
            full_path = os.path.join(Path(__file__).parent.resolve())
            return send_from_directory(full_path, request_dict['endpoint'])

        # Try to get authentication from the cookie
        cookie_name = request_dict['cookies'].get('token', None)
        print(f'Incomming Cookie name: {cookie_name}')
        if cookie_name:  # We get a token... lets verify if its legitimate, and still alive
            cookie = self._get_local_cookie(cookie_name)
            if cookie: # Already authenticated --> Lets tunnel info back to client
                print(f'AUTHENTICATED: Cookie {cookie_name} exists in local')
                if request_dict['endpoint'] == '/': # If path is the root, lets go to the configured initial entrypoint.
                    method = cookie['method']
                    path = cookie['endpoint']
                    headers = {}
                    if method == 'GET':
                        params = cookie['params']
                    else:
                        data = cookie['content']
                else:
                    method = request_dict['method']
                    path = request_dict['endpoint']
                    headers = request_dict['headers']
                    params = request_dict['params']
                    data = request_dict['data']
                # Lets get the response from the internal host, and tunnel it back to client
                if method == 'GET':
                    response = self._call_inner_get(cookie['host'], path, params, headers)
                else:
                    response = self._call_inner_post(cookie['host'], path, data, headers)
            else: # We got a token, but its no longer valid --> ask again for credentials
                print(f'NOT AUTHENTICATED: Cookie {cookie_name} DOESNT exist in local')
                response = self._reask_credentials(request_dict, cookie_name)
        else:  # Not authenticated yet... lets pop the authentication popup to the user
            print('Not authenticated yet')
            response = self._first_auth_and_redirect(request_dict)

        return response
