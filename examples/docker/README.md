# Docker deployment

This directory contains an example deployment of Brink using docker-compose.

In this example, Brink is deployed together with Dex as the OpenID Connect provider. 
The ports of both services are forwarded to the host machine to mimic a "public" network.

As examples targets, some databases or services are included:

- redis
- postgres
- nginx
- [parttysh](https://github.com/caarlos0/parttysh) (a funny ssh service to demonstrate ssh connectivity)

Those targets are not port forwarded to the host machine in order to mimic them residing in a private network.

Brink is configured to allow `john@local` to access specific ports of the targets.
Clients can reach these targets via Brink, but only user `john@local` is allowed to access them.

## Getting started

Start all services with docker-compose:

```bash
$ docker-compose up -d
```

Once the deployment is running, you can authenticate to Brink:

```bash
$ brink auth login -r http://localhost:7000
```

A browser will open and redirect you to the login form of Dex, enter the email `john@local` and password `password` to login.
You should receive a "Authorization successful" message. Close the browser tab and return to your terminal.

## Local port forwarding

In this first example, you "bring back" a private remote service to your local machine, e.g. nginx:

```bash
$ brink connect -r http://localhost:7000 -t nginx:80 -p 8080
```

> You could read this command as: _"Bring the remote nginx running on port 80 to my local machine on port 8080 via a Brink proxy running on http://localhost:7000"_

Now the tunnel is running, open a browser and go to http://localhost:8080, you should see the nginx default page.
Or open a second terminal and use `curl`:

```bash
$ curl http://localhost:8080
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

```

## Exec command

The `brink connect` can execute clients with the Brink tcp tunnel. 
For example, we'll use redis-cli to ping the Redis container via Brink:

```bash
$ brink connect -r http://localhost:7000 -t redis:6379 --exec redis-cli -- -p {{brink.port}} ping
PONG
```

## SSH sessions

brink has built-in support for SSH connections:

```bash
brink ssh -r http://localhost:7000 -t parttysh:2222
```