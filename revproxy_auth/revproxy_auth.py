""" Class to perform authentication using the synology authmethods """
import os
import time
from urllib import parse
import json
from pathlib import Path
import secrets
import jinja2
import requests
from flask import Flask, request, Response, send_from_directory, redirect, Request

from config_yml import Config

COOKIE_LIFE_MINUTES = 15

HTTP_200_OK = 200
HTTP_501_NOT_IMPLEMENTED = 501

class RevProxyAuth():
    """ 
    Class to manage the authentication. 
    The path_redirect function should be called from a '/<path:path>' flask rule
    Also a rule '/' should call this function like this:  return self.auth_proxy.path_redirect("/")
    """
    def __init__(self, app: Flask,
                 root_class: str='revproxy_auth',
                 template_config_path: str=None,
                 dry_run=False) -> None:
        """
            template_config_path: full path of configuration template
        """

        if not template_config_path:
            template_config_path = os.path.join(Path(__file__).parent.resolve(), './config-template.yml')

        self._config = Config(root_class, template_config_path, 'revproxy_auth_config.yml', dry_run=dry_run)

        self.homevar = os.path.join(str(Path.home()), 'var', root_class)

        self.auth_cookie_folder = os.path.join(self.homevar, 'auth_cookies')
        if not os.path.exists(self.auth_cookie_folder):
            os.makedirs(self.auth_cookie_folder)
        self.session_cookie_folder = os.path.join(self.homevar, 'session_cookies')
        if not os.path.exists(self.session_cookie_folder):
            os.makedirs(self.session_cookie_folder)
        self.app = app
        self.app.add_url_rule(rule='/revproxy_auth_static/<path:path>',
                              view_func=self._get_static_content,
                              methods=['GET', 'POST'])

    def token_valid(self, req):
        """ Checks if the token in the request matches an existing and not-expired cookie file
        Args:
            req (Request): Http request
        Returns:
            bool: True if token matches cookie file, and its not expired yet
        """
        valid = False
        cookie_name = req.cookies.get('token', None)
        if cookie_name:  # We get a token... lets verify if its legitimate, and still alive
            valid = not self._clear_local_cookie_if_expired(self.auth_cookie_folder, cookie_name)
        return valid

    def get_auth_response(self, req, callback) -> Response:
        """ If valid auth token comes fromt he client, return none
            Otherwise, it will return a response so that the client opens again the Auth Popup
        Returns:
            Response: Http response with the auth popup, or 
                      None if auth request is not needed because already are authenticated
        """
        response = None

        if req.form.get('revproxy_auth', None):
            print('Credentials validated by synology NAS')
            session_cookie, session_cookie_name = self._creates_session_token_from_popup_data(req)
            if session_cookie_name:
                # To get rid of the POST form data, and reenter with the valid session token
                response = redirect(parse.urljoin(session_cookie['host'], session_cookie['endpoint']))
                response.set_cookie('token', session_cookie_name, max_age=COOKIE_LIFE_MINUTES*60)
            else:
                response = self._reask_credentials(req)
        else:
            # Try to get authentication from the cookie
            cookie_name = req.cookies.get('token', None)
            print(f'Incomming Session token Cookie name: {cookie_name}')
            if cookie_name:
                # We get a session token... lets verify if its legitimate, and still alive
                cookie = self._get_local_session_cookie(cookie_name)
                if cookie: # Already authenticated --> Lets tunnel info back to client
                    print(f'AUTHENTICATED: Session Token Cookie {cookie_name} exists in local')
                    response = callback()
                else: # We got a session, but its no longer valid --> ask again for credentials
                    print(f'NOT AUTHENTICATED: Session Token Cookie {cookie_name} DOESNT exist in local')
                    response = self._reask_credentials(req, old_cookie_name=cookie_name)
            else:  # No session cookie... and no form data with credendials
                response = self._reask_credentials(req)

        return response

    def path_redirect(self, path) -> Response:
        """Main entry point
        Returns:
            http_response: response string
        """
        print(f'---------------------- Path requested: {path} --------------------')
        resp = self._path_redirect(request)
        return resp

    def _build_auth_cookie(self, req: Request) -> tuple:
        mapping_info = self._config['mapping'].get(req.host)
        if not mapping_info:
            return None, None

        host = mapping_info.get('host')
        endpoint = mapping_info.get('endpoint')
        method = mapping_info.get('method')

        ser_head = {}
        for head in req.headers:
            ser_head[head[0]] = head[1]
        headers = json.dumps(ser_head)

        # Stores the internal URL into a cookie file to be read later
        cookie_name = secrets.token_urlsafe(16)
        content = str(req.data)
        cookie = {'host': host,
                  'endpoint': endpoint, 
                  'method': method,
                  'params': req.query_string.decode("utf-8"), 
                  'headers': headers,
                  'content': content}

        return cookie, cookie_name

    def _build_session_cookie(self, auth_cookie: dict) -> tuple:
        # cookie = {'session': True,
        #           'endpoint': parse.urljoin(auth_cookie['host'], auth_cookie['endpoint'])
        #          }
        cookie = auth_cookie
        return cookie, secrets.token_urlsafe(16)

    def _get_static_content(self, path: str):
        """Get revproxy_auth custom static content
        Args:
            path (str): Resource to be retrieved from revproxy_aut_static folder

        Returns:
            _type_: Resouce
        """
        full_path = os.path.join(Path(__file__).parent.resolve(), 'revproxy_auth_static')
        return send_from_directory(full_path, path)

    def _write_cookie(self, cookie: dict, cookie_folder: str, cookie_name: str):
        self._clear_expired_cookies(cookie_folder) # Housekeeping before writting new

        cookie_path = os.path.join(cookie_folder, cookie_name)
        with open(cookie_path, 'w', encoding="utf-8") as cookie_file:
            json.dump(cookie, cookie_file)

    def _clear_local_cookie(self, cookie_folder: str, cookie_name: str):
        cleared = False
        cookie_file_name = os.path.join(cookie_folder, cookie_name)
        if os.path.isfile(cookie_file_name):
            cleared = True
            os.remove(cookie_file_name)
        return cleared

    def _clear_local_cookie_if_expired(self, cookie_folder: str, cookie_name: str):
        cleared = False
        cookie_file_name = os.path.join(cookie_folder, cookie_name)
        if os.path.isfile(cookie_file_name):
            age = time.time() - os.path.getmtime(cookie_file_name)
            if age > COOKIE_LIFE_MINUTES*60:
                cleared = True
                os.remove(cookie_file_name)
        return cleared

    def _clear_expired_cookies(self, cookie_folder: str):
        for filename in os.listdir(cookie_folder):
            self._clear_local_cookie_if_expired(cookie_folder, filename)

    def _build_auth_popup(self, cookie_name: str) -> Response:
        # Get the auth html form template and send back to the user, so he can authenticate
        form_path = os.path.join(Path(__file__).parent.resolve(), 'templates', 'form.html')
        with open(form_path, 'r', encoding="utf8") as form:
            buff = form.read()
            # replace the cookie name
            env = jinja2.Environment()
            template = env.from_string(buff)
            content = template.render(revproxy_auth=cookie_name)
            return Response(content, status=HTTP_200_OK,  content_type='text/html')

    def _get_local_auth_cookie(self, cookie_name:str = None):
        cookie = None
        if cookie_name:
            cookie_path = os.path.join(self.auth_cookie_folder, cookie_name)
            if os.path.exists(cookie_path):
                with open(cookie_path, 'r', encoding="utf-8") as cookie_file:
                    cookie = json.load(cookie_file)

                    cookie['headers'] = json.loads(cookie['headers'])
        return cookie

    def _get_local_session_cookie(self, cookie_name:str = None):
        cookie = None
        if cookie_name:
            cookie_path = os.path.join(self.session_cookie_folder, cookie_name)
            if os.path.exists(cookie_path):
                with open(cookie_path, 'r', encoding="utf-8") as cookie_file:
                    cookie = json.load(cookie_file)
        return cookie

    def _credentials_valid(self, form):
        token = form.get('revproxy_auth', None)
        if token:
            user = form.get('user', '').strip(' \t\n\r')
            password = form.get('password', '').strip(' \t\n\r')
            otp = form.get('OTP', '').strip(' \t\n\r')
            testing_credentials = self._config['testing_credentials']
            if not testing_credentials:
                url = (f'{self._config["NAS"]}/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login'
                       f'&account={user}&passwd={password}&otp_code={otp}')
                auth_response = requests.get(url, timeout=10)
                # Verify authentication
                return auth_response.json()['success']
            else: # Testing credentiales
                return user == testing_credentials['user'] and \
                       password == testing_credentials['password'] and \
                       otp == testing_credentials['OTP']
        return False

    def _call_inner_get(self, host, endpoint, params, headers) -> Response:
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.get(fullpath,
                            params=params,
                            headers = headers,
                            timeout=10)
        return Response(resp.text, status=resp.status_code, content_type=resp.headers['content-type'])

    def _call_inner_post(self, host, endpoint, data, headers) -> Response:
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.post(fullpath,
                             data = data,
                             headers = headers,
                             timeout=10)
        return Response(resp.text, status=resp.status_code, content_type=resp.headers['content-type'])

    def _reask_credentials(self, req: Request, old_cookie_name: str = None) -> Response:
        new_cookie, new_cookie_name = self._build_auth_cookie(req)
        if not new_cookie: # Unable to build cookie for requested path: host unknown
            return Response(f'Host {req.host} not found on revproxy_auth config translation table',
                            status=HTTP_501_NOT_IMPLEMENTED, 
                            content_type='text/plain')
        print(f'Creating new auth cookie {new_cookie_name} and reasking to user...')
        self._write_cookie(new_cookie, self.auth_cookie_folder, new_cookie_name)
        response = self._build_auth_popup(new_cookie_name)
        if old_cookie_name:
            print(f'Deleting cookie in response: {old_cookie_name}')
            self._clear_local_cookie(self.auth_cookie_folder, old_cookie_name)
        return response

    def _creates_session_token_from_popup_data(self, req: Request) -> str:
        """ Creates valid session token if valid credentials sent from the auth popup
        Args:
            req (Request): Request fro client... hopefully with valod auth credentials

        Returns:
            Tuple(dict, str): Dict with the new session cookie created (None if credentials invalid or not found)
                              str with the name of the session cookie created
        """
        session_cookie_name = None
        session_cookie = None
        cookie_name = req.form.get('revproxy_auth', None)
        auth_cookie = self._get_local_auth_cookie(cookie_name)
        if auth_cookie:
            if self._credentials_valid(req.form):
                print(f'Auth Local cookie {cookie_name} still alive and valid.')
                session_cookie, session_cookie_name = self._build_session_cookie(auth_cookie)
                print(f'Creating new session cookie {session_cookie_name} and reasking to user...')
                self._write_cookie(session_cookie, self.session_cookie_folder, session_cookie_name)
            else:
                print(f'Auth Local cookie {cookie_name} still alive but credentials are invalid.')
        else:
            print(f'Auth Local cookie {cookie_name} doesnt exist.')
        return session_cookie, session_cookie_name

    def _first_auth_and_redirect(self, req: Request) -> Response:
        cookie_name = req.form.get('revproxy_auth', None)
        cookie = self._get_local_auth_cookie(cookie_name)
        if cookie:
            print(f'Local cookie {cookie_name} still alive')
            if self._credentials_valid(req.form):
                print('Credentials validated by synology NAS')
                # Search for the cookie and redirect to related URL if present
                if cookie['method'] == 'GET':
                    response = self._call_inner_get(cookie['host'], cookie['endpoint'], cookie['params'], cookie['headers'])
                else:
                    response = self._call_inner_post(cookie['host'], cookie['endpoint'], cookie['content'], cookie['headers'])
                response.set_cookie('token', cookie_name, max_age=COOKIE_LIFE_MINUTES*60)
            else: # We come from the auth popup, but credentials are invalid --> ask again for credentials
                print('Credentials rejected by synology NAS. Reopening auth popup')
                response = self._build_auth_popup(cookie_name)
        else: # We got a token, but its no longer valid --> ask again for credentials
            print('Local cookie expired. Reopening auth popup')
            response = self._reask_credentials(req, cookie_name)
        return response

    def _path_redirect(self, req: Request) -> Response:
        """ Flask independent internal function
        Returns:
            http_response: response string
        """
        if req.path == '/favicon.ico':
            cookie, cookie_name = self._build_auth_cookie(req)
            if not cookie: # Unable to build cookie for requested path: host unknown
                return Response(req.path, status=501, content_type='text/plain')
            print(f"favicon.ico requested: Directly returning from inner endpoint {cookie['host']}")
            if req.url == parse.urljoin(cookie['host'], req.path):
                return Response(req.path, status=400, content_type='text/plain')
            return self._call_inner_get(host=cookie['host'],
                                        endpoint=req.path,
                                        params=req.query_string.decode("utf-8"),
                                        headers=req.headers)

        if req.path.startswith('revproxy_auth_static'):
            return self._get_static_content(req.path)

        if req.form.get('revproxy_auth', None):
            session_cookie, session_cookie_name = self._creates_session_token_from_popup_data(req)
            if session_cookie_name:
                print('Credentials validated by synology NAS')
                if session_cookie['method'] == 'GET':
                    response = self._call_inner_get(session_cookie['host'], session_cookie['endpoint'], session_cookie['params'], {})
                else:
                    response = self._call_inner_post(session_cookie['host'], session_cookie['endpoint'], session_cookie['content'], {})
                # # To get rid of the POST form data, and reenter with the valid session token
                # response = redirect(session_cookie['endpoint'])
                response.set_cookie('token', session_cookie_name, max_age=COOKIE_LIFE_MINUTES*60)
            else:
                response = self._reask_credentials(req)
        else:
            # Try to get authentication from the cookie
            cookie_name = req.cookies.get('token', None)
            print(f'Incomming Session token Cookie name: {cookie_name}')
            if cookie_name:
                # We get a session token... lets verify if its legitimate, and still alive
                cookie = self._get_local_session_cookie(cookie_name)
                if cookie: # Already authenticated --> Lets tunnel info back to client
                    print(f'AUTHENTICATED: Session Token Cookie {cookie_name} exists in local')
                    # response = callback()
                    if req.path == '/': # If path is the root, lets go to the configured initial entrypoint.
                        method = cookie['method']
                        path = cookie['endpoint']
                        headers = {}
                        if method == 'GET':
                            params = cookie['params']
                        else:
                            data = cookie['content']
                    else:
                        method = req.method
                        path = req.path
                        headers = req.headers
                        params = req.query_string.decode("utf-8")
                        data = req.data
                    # Lets get the response from the internal host, and tunnel it back to client
                    if method == 'GET':
                        response = self._call_inner_get(cookie['host'], path, params, headers)
                    else:
                        response = self._call_inner_post(cookie['host'], path, data, headers)
                else: # We got a session, but its no longer valid --> ask again for credentials
                    print(f'NOT AUTHENTICATED: Session Token Cookie {cookie_name} DOESNT exist in local')
                    response = self._reask_credentials(req, old_cookie_name=cookie_name)
            else:  # No session cookie... and no form data with credendials
                response = self._reask_credentials(req)
      
        return response
