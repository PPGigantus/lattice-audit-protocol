# Kubernetes Baseline (LAP Gateway)

This folder provides a **safe-by-default Kubernetes baseline** for running the LAP Gateway behind an ingress/reverse-proxy, with NetworkPolicies that enforce the core boundary assumption:

- tools are only reachable from the **gateway**, not from agents directly
- the gateway is not directly exposed (use an Ingress / reverse proxy)

> **NetworkPolicies require a CNI that enforces them** (Calico/Cilium/etc). If your cluster ignores NetworkPolicies, you must enforce isolation another way.

## What’s included

- `manifests/` — plain Kubernetes YAML
- `helm/` — a minimal Helm chart (`lap-gateway/`)
- `scripts/` — helper scripts for generating secrets

## Quick start (manifests)

### 0) Prereqs

- A Kubernetes cluster
- A CNI that enforces NetworkPolicies
- An ingress controller (optional, but recommended). Examples: NGINX Ingress Controller, Traefik, Istio.

### 1) Build and publish an image

You need to build a container image for the gateway and push it to a registry your cluster can pull from.

Example:

```bash
# from repo root
docker build -t your-registry/lap-gateway:1.0.7 -f deploy/k8s/Dockerfile.gateway .
docker push your-registry/lap-gateway:1.0.7
```

### 2) Create namespace

```bash
kubectl apply -f manifests/00-namespace.yaml
```

### 3) Create secrets

Edit `manifests/10-secret.template.yaml` and replace values, or generate from environment:

```bash
export LAP_GATEWAY_SIGNING_KEY="<64-hex>"
export LAP_API_KEYS_JSON='{"dev-key-1":"agent_001"}'
# optional
# export LAP_TRUSTED_REVIEWER_KEYS_JSON='{"reviewer-key-1":"<pubhex>"}'

bash scripts/make_secret_yaml.sh > /tmp/lap-gateway-secret.yaml
kubectl -n lap-system apply -f /tmp/lap-gateway-secret.yaml
```

### 4) Apply config + policies + gateway

```bash
kubectl -n lap-system apply -f manifests/20-configmap.yaml
kubectl -n lap-system apply -f manifests/30-networkpolicies.yaml
kubectl -n lap-system apply -f manifests/40-gateway.deployment.yaml
kubectl -n lap-system apply -f manifests/41-gateway.service.yaml
```

### 5) Optional: deploy demo tool (only reachable from gateway)

```bash
kubectl -n lap-system apply -f manifests/50-demo-tool.deployment.yaml
kubectl -n lap-system apply -f manifests/51-demo-tool.service.yaml
```

Then set `LAP_HTTP_TOOL_URL=http://lap-demo-tool:9000` in the ConfigMap.

### 6) Optional: Ingress

If you use an ingress controller, apply:

```bash
kubectl -n lap-system apply -f manifests/60-ingress.yaml
```

Update `hosts:` and TLS settings in the manifest to match your domain.

## Quick start (Helm)

```bash
helm install lap-gateway helm/lap-gateway \
  --namespace lap-system --create-namespace \
  --set image.repository=your-registry/lap-gateway \
  --set image.tag=1.0.7 \
  --set secrets.signingKey="<64-hex>" \
  --set secrets.apiKeysJson='{"dev-key-1":"agent_001"}'
```

## Boundary check

To validate isolation, from an **agent pod** in the same namespace:

- calling the gateway service should work
- calling the demo tool service directly should be blocked by NetworkPolicy

