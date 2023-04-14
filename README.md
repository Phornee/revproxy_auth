# Authproxy
This class implements a reverse proxy intended to work inside a Flask server, allows to use the synology auth credentials for all your services behind the synology service proxy.
Have you setup the reverse proxy in your synology NAS, but don´t want that everyone who knows your services´ URL can have access to your services?
This repo will allow you to restrict the access from internet to your internal Api REST webservices, using the credentials and users that you have created in your Synology NAS.
It will also request the OTP code if you have that configured in your NAS.

The steps are simple:

1. You need to make available a new service inside your LAN with the authproxy.
2. You may want to include synology-revproxy-auth as part of you already existing services... no need to create an specific flask or any newwsgi just for this. Just make the API REST call available.
3. Configure the service so that it can redirect all the requests to the proper internal host & port.
4. Create all your entry points in the synology reverse procy menu, and make all of them point to the authproxy endpoint
