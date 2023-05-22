# revproxy_auth
This class implements a reverse proxy intended to work inside a Flask server, allows to use the synology auth credentials for all your services behind the synology service proxy.
Have you setup the reverse proxy in your synology NAS, but don´t want that everyone who knows your services´ URL can have access to your services?
This repo will allow you to restrict the access from internet to your internal Api REST webservices, using the credentials and users that you have created in your Synology NAS.
It will also request the OTP code if you have that configured in your NAS.

Configuration yml file will be place in the /home/var/{yourservicename}

Revproxy_auth can work in two mode:

1. Embeded. You can embed the authentication by modifying your Flask based service:
    self.app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    self.revproxy_auth = RevProxyAuth(self.app, root_class='yourservicename')
    self.app.add_url_rule('/', 'index', self.main_endpoint, methods=['GET', 'POST'])
    ...
    def main_endpoint(self):
        """ Main endpoint that returns the main page for your service
        Returns:
            response: The main html content
        """
        return self.revproxy_auth.get_auth_response(request, lambda : render_template('form.html'))

2. Proxy
    You need to make available a new service inside your LAN with the authproxy.
    You may want to include revproxy-auth as part of you already existing services... no need to create an specific flask or any newwsgi just for this. Just make the API REST call available.
    Configure the service in the config.yml so that it can redirect all the requests to the proper internal host & port.
    Create all your entry points in the synology reverse proxy menu, and make all of them point to the authproxy endpoint
