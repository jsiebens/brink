# brink

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/jsiebens/brink/master/LICENSE)
[![test](https://img.shields.io/github/actions/workflow/status/jsiebens/brink/build.yaml?branch=main)](https://github.com/jsiebens/brink/actions)
[![report](https://goreportcard.com/badge/github.com/jsiebens/brink)](https://goreportcard.com/report/github.com/jsiebens/brink)

__brink__ is a lightweight Identity-Aware Proxy (IAP) for TCP forwarding. 

It allows you to establish a secure websocket connection over which you can forward SSH, RDP, 
and other traffic to your private services, and allows you to control who can access those services based on identity. 

Highlights:

- access your private services from anywhere
- identity-based access for zero-trust security
- authenticate with GitHub or with any trusted OIDC provider
- access policies based on identity
- a single binary or Docker image
- easy configuration

## Quickstart

Create an OIDC client application on your favorite provider, e.g. Auth0, Okta, Keycloak, ... or create a
new [GitHub OAuth](https://github.com/settings/developers) application. In both cases, take note of your client id and
client secret (and the issuer url when using OIDC).

Create a new brink configuration file:

```yaml
tls:
  disable: true

auth:
  url_prefix: "http://localhost:7000"
  provider:
    type: "oidc" # or github
    issuer: "<your oidc issuer>" # remove this line when using github
    client_id: "<your client id>"
    client_secret: "<your client secret>"

proxy:
  policies:
    local:
      filters: [ "*" ]
      targets: [ "localhost:*" ]
```

Download the latest version of brink from the [releases](https://github.com/jsiebens/brink/releases) page

Start a brink server instanc:

```shell
$ brink server proxy --config config.yaml
INFO[0000] Starting brink proxy server. Version 0.6.0 - 83c874a 
INFO[0000] registering oidc routes                      
INFO[0000] registering proxy routes                     
INFO[0000] server listening on :7000
```

Next, use the `brink ssh` command to SSH into the localhost. Depending on your system, a browser will first open
allowing you to authenticate with your identity provider.

```shell
$ brink ssh -r http://localhost:7000 -t localhost:22
```

## Documentation

(coming soon; in the meanwhile, have a look at the examples below)

## Examples

- [Running brink with docker-compose](./examples/docker)
- [Running brink on Kubernetes]((./examples/kubernetes))

## Live demo

Download the latest version of brink from the [releases](https://github.com/jsiebens/brink/releases) page, connect to
the demo environment and enjoy a dancing parrot over SSH.

```shell
$ brink ssh -r brink.j5s.io -t parttysh:2222
```
