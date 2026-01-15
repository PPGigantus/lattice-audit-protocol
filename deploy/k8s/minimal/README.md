# Minimal bypass-resistant Kubernetes templates

These manifests are a **minimal** starting point that demonstrates the core non-bypassable boundary:

- **Agents call the gateway**
- **Only the gateway can call tools** (enforced by NetworkPolicy)

> If agent pods can reach tool endpoints directly, LAP is only **logging**, not **enforcement**.

## Apply

```bash
kubectl create namespace lap-system || true
kubectl -n lap-system apply -f gateway.deployment.yaml -f gateway.service.yaml
kubectl -n lap-system apply -f tool-service.deployment.yaml -f tool-service.service.yaml
kubectl -n lap-system apply -f networkpolicy-gateway-to-tool.yaml
# Optional: lock agent pods down
kubectl -n lap-system apply -f networkpolicy-agent-deny-egress.yaml
```

## Notes

- You will need a CNI that enforces NetworkPolicies (Calico/Cilium/etc.).
- These are templates: set images, secrets, and ingress/LB according to your environment.
- For a more complete baseline (namespace, secrets, ingress examples), see `deploy/k8s/manifests/`.
