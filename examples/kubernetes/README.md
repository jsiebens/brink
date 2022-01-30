# Kubernetes deployment

This directory contains an example deployment of Brink using Kubernetes.

## Getting started

### Requirements

- a Kubernetes cluster, e.q. minikube, KinD or a cluster on a cloud provider
- a OIDC client id and client secret (with callback url `http://localhost:7000/a/callback`) on you favorite IdP provider e.g. Auth0, Okta, Keycloak, ...

### Deploy 

Create the target environments:

```bash
kubectl create namespace development
kubectl create namespace production

kubectl apply -f ./app -n development
kubectl apply -f ./app -n production
```

Create a namespace for Brink deployment:

```bash
kubectl create namespace brink
```

Create a secret with your OIDC issuer, client id and client secret:

```bash
kubectl create secret generic brink-oidc \
    --namespace brink \
    --from-literal=BRINK_AUTH_PROVIDER_ISSUER=<your oidc issuer> \
    --from-literal=BRINK_AUTH_PROVIDER_CLIENT_ID=<your oidc client id> \
    --from-literal=BRINK_AUTH_PROVIDER_CLIENT_SECRET=<your oidc client secret>
```

Deploy the Brink services:

```bash
kubectl apply -f ./brink -n brink
```

Expose all 3 Brink services running on your Kubernetes, on your local host using `kubectl port-forward` (you'll need to
do this in 3 separate long running shells):

```shell
kubectl port-forward -n brink pods/$(kubectl get pods -n brink | grep brink-auth | cut -d " " -f 1) 7000:7000 &
kubectl port-forward -n brink pods/$(kubectl get pods -n brink | grep brink-dev | cut -d " " -f 1)  7001:7000 &
kubectl port-forward -n brink pods/$(kubectl get pods -n brink | grep brink-prod | cut -d " " -f 1) 7002:7000 &
```

## Local port forwarding

In this first example, you "bring back" a private remote service to your local machine, e.g. redis.

Redis is deployed in two different environments, `development` and `production`, and is only accessible via the correct Brink proxy instance.

For development, the Brink proxy is available at http://localhost:7001 (via kubectl port-forwarding):

```bash
$ brink connect -r http://localhost:7001 -t redis.development.svc:6379

  Listening on 127.0.0.1:46483
  
```

For production, the Brink proxy is available at http://localhost:7002 (via kubectl port-forwarding):

```bash
$ brink connect -r http://localhost:7002 -t redis.production.svc:6379

  Listening on 127.0.0.1:46337
  
```

Both will use the same Brink authentication server and the same OIDC configuration.

Trying to access the production redis via the development proxy will not succeed because of the configured policies.

```bash
$ brink connect -r http://localhost:7001 -t redis.production.svc:6379
Error: unexpected status code: 400 - access to target [redis.production.svc:6379] is denied
```

## Exec command

The `brink connect` can execute clients with the Brink tcp tunnel.
For example, we'll use redis-cli to ping the Redis container via Brink:

```bash
$ brink connect -r http://localhost:7001 -t redis.development.svc:6379 --exec redis-cli -- -p {{brink.port}} ping
PONG
```

## SSH sessions

Brink has built-in support for SSH connections:

```bash
$ brink ssh -r http://localhost:7001 -t parttysh.development.svc:2222
```