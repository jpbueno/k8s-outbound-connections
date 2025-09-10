# Discovering Outbound Connections from Kubernetes Pods

## Part A: Static Analysis

### Step 1: Analyze Network Policies for Outbound Rules

```bash
kubectl get networkpolicies --all-namespaces -o wide
kubectl get networkpolicy <policy-name> -n <namespace> -o yaml
```

### Step 2: Check Istio Service Mesh External Services

```bash
kubectl get serviceentries --all-namespaces -o wide
kubectl get destinationrules --all-namespaces -o wide
```

### Step 3: Analyze Pod Configurations for External Endpoints

```bash
kubectl get pods --all-namespaces -o=jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{range .spec.containers[*]}{range .env[*]}{.name}{"="}{.value}{"\n"}{end}{end}{end}' \
| grep -E "(http://|https://|\.com|\.io|\.net|\.org|\.ai)"
```

### Step 4: Check Container Images for External Registries

```bash
kubectl get pods --all-namespaces -o yaml | grep "image:" | grep -v "cluster.local" | sort | uniq
```

### Step 5: Search Pod Logs for External API Calls

```bash
kubectl logs <pod-name> -n <namespace> --tail=100 | grep -E "(http://|https://)"
```

### Step 6: Check DNS Query Logs

```bash
kubectl logs <coredns-pod> -n kube-system --tail=100 \
| grep -v "cluster.local" \
| grep -E "\.com|\.io|\.net|\.org|\.ai"
```

---

## Part B: Real-Time Outbound Traffic Monitoring

### Method 1: Enable Istio Access Logging

**Enable comprehensive access logging for all Istio-managed pods:**

```bash
kubectl patch configmap istio -n istio-system --type merge -p='{"data":{"mesh":"defaultConfig:\n  discoveryAddress: istiod.istio-system.svc:15012\n  # Enable access logging for outbound traffic\n  proxyMetadata:\n    PILOT_ENABLE_ACCESS_LOG: \"true\"\n  # Log format including upstream hosts\n  proxyStatsMatcher:\n    inclusionRegexps:\n    - \".*outlier_detection.*\"\n    - \".*circuit_breakers.*\"\n    - \".*upstream_rq_retry.*\"\n    - \".*_cx_.*\"\n  tracing:\n    zipkin:\n      address: zipkin.istio-system:9411\ndefaultProviders:\n  metrics:\n  - prometheus\nenablePrometheusMerge: true\nrootNamespace: istio-system\ntrustDomain: cluster.local\nextensionProviders:\n- name: otel\n  envoyOtelAls:\n    service: opentelemetry-collector.istio-system.svc.cluster.local\n    port: 4317"}}'
```

**Enable access logs on Envoy sidecars:**

```bash
kubectl apply -f - <<EOF
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: default
  namespace: istio-system
spec:
  accessLogging:
  - providers:
    - name: envoy
EOF
```

**Monitor outbound traffic in real-time:**

```bash
kubectl logs -f -l app=istio-proxy --all-namespaces | grep -E "(outbound|upstream_host)"
```

---

### Method 2: Enable Verbose CoreDNS Logging

**Enable detailed DNS query logging:**

```bash
kubectl get configmap coredns -n kube-system -o yaml > coredns-backup.yaml

kubectl patch configmap coredns -n kube-system --type merge -p='{"data":{"Corefile":".:53 {\n    log {\n        class denial error\n    }\n    errors\n    health {\n       lameduck 5s\n    }\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n       pods insecure\n       fallthrough in-addr.arpa ip6.arpa\n       ttl 30\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf {\n       max_concurrent 1000\n    }\n    cache 30\n    loop\n    reload\n    loadbalance\n}"}}'
```

**Restart CoreDNS to apply changes:**

```bash
kubectl rollout restart deployment/coredns -n kube-system
```

**Monitor DNS queries in real-time:**

```bash
kubectl logs -f -l k8s-app=kube-dns -n kube-system | grep -v "cluster.local"
```

---

### Method 3: Deploy Network Monitoring with Cilium Hubble

**If using Cilium CNI, enable Hubble for network observability:**

```bash
# Check if Cilium is installed
kubectl get pods -n kube-system | grep cilium

# Enable Hubble if Cilium is present
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  hubble-enabled: "true"
  hubble-socket-enabled: "true"
  hubble-metrics-enabled: "dns,drop,tcp,flow,icmp,http"
EOF
```

**Monitor real-time traffic:**

```bash
kubectl exec -n kube-system <cilium-pod> -- hubble observe --follow --type trace
```

---

### Method 4: Deploy Falco for Security Monitoring

**Install Falco to monitor outbound network connections:**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true
```

**Create custom rule for outbound monitoring:**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules-outbound
  namespace: falco-system
data:
  outbound_rules.yaml: |
    - rule: Outbound Connection from Pod
      desc: Detect outbound network connections from pods
      condition: >
        outbound and 
        not fd.ip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and
        not fd.ip in (127.0.0.0/8)
      output: >
        Outbound connection detected (user=%user.name verb=%ka.verb 
        uri=%ka.uri.param pod=%ka.target.pod container=%container.name 
        dest_ip=%fd.ip dest_port=%fd.port proto=%fd.l4proto)
      priority: INFO
EOF
```

---

### Method 5: Node-Level Network Monitoring

**Monitor active connections on cluster nodes:**

```bash
# Check active outbound connections
kubectl debug node/<node-name> -it --image=nicolaka/netshoot -- ss -tuln | grep -E ":(80|443|53)"

# Monitor real-time connections
kubectl debug node/<node-name> -it --image=nicolaka/netshoot -- watch -n 2 'ss -tuln | grep ESTAB'
```

---

### Method 6: Pod-Specific Traffic Capture

**Capture traffic from specific pods using tcpdump:**

```bash
# Attach a debug container to target pod's network namespace
kubectl debug <target-pod> -n <namespace> -it --image=nicolaka/netshoot --target=<container-name> -- \
  tcpdump -i any -n 'not host 10.96.0.1 and not net 10.0.0.0/8'

# Or capture specific protocols
kubectl debug <target-pod> -n <namespace> -it --image=nicolaka/netshoot --target=<container-name> -- \
  tcpdump -i any -n 'port 80 or port 443'
```

---

### Method 7: Enhanced CoreDNS Query Logging

**Enable comprehensive DNS query logging:**

```bash
kubectl patch configmap coredns -n kube-system --type merge -p='{"data":{"Corefile":".:53 {\n    log . {\n        class all\n    }\n    errors\n    health {\n       lameduck 5s\n    }\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n       pods insecure\n       fallthrough in-addr.arpa ip6.arpa\n       ttl 30\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf {\n       max_concurrent 1000\n    }\n    cache 30\n    loop\n    reload\n    loadbalance\n}"}}'

kubectl rollout restart deployment/coredns -n kube-system
```

**Monitor all DNS queries in real-time:**

```bash
kubectl logs -f -l k8s-app=kube-dns -n kube-system \
| grep -E "(\.com|\.io|\.net|\.org|\.ai)" \
| grep -v "cluster.local"
```

---

### Method 8: Prometheus + Grafana Egress Monitoring

**Create ServiceMonitor for egress metrics:**

```bash
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: istio-proxy-egress
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: istio-proxy
  endpoints:
  - port: http-monitoring
    interval: 15s
    path: /stats/prometheus
    params:
      filter:
      - 'cluster\.outbound.*'
EOF
```

---

## Method 9: Deploy eBPF-based Network Monitoring

**Install Cilium with Hubble for comprehensive network visibility:**

```bash
# If not using Cilium, install it with Hubble enabled
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true
```

**Real-time outbound monitoring:**

```bash
# Install Hubble CLI
curl -L --remote-name-all https://github.com/cilium/hubble/releases/latest/download/hubble-linux-amd64.tar.gz
tar xzvfC hubble-linux-amd64.tar.gz /usr/local/bin

# Monitor outbound traffic
hubble observe --follow --type trace --verdict ALLOWED | grep -v "cluster.local"
```

---

## Real-Time Monitoring Commands Summary

### Immediate Commands (No Installation Required)

1. **Monitor Istio proxy logs:**

   ```bash
   kubectl logs -f -l app=istio-proxy --all-namespaces | grep -E "(outbound|upstream)"
   ```
2. **Monitor DNS queries:**

   ```bash
   kubectl logs -f -l k8s-app=kube-dns -n kube-system | grep -v "cluster.local"
   ```
3. **Monitor pod network connections:**

   ```bash
   kubectl debug <pod-name> -n <namespace> -it --image=nicolaka/netshoot -- netstat -tuln
   ```
4. **Capture live traffic:**

   ```bash
   kubectl debug node/<node-name> -it --image=nicolaka/netshoot -- \
     tcpdump -i any -n 'not net 10.0.0.0/8 and not net 172.16.0.0/12 and not net 192.168.0.0/16'
   ```

### Advanced Monitoring Setup

1. **Istio access logging** — Comprehensive HTTP/HTTPS traffic logs
2. **Cilium Hubble** — eBPF-based network flow monitoring
3. **Falco** — Security-focused network monitoring with custom rules
4. **Enhanced CoreDNS logging** — Complete DNS query visibility

---

## Interpreting Results

* **DNS queries** show what external domains pods are trying to reach.
* **Access logs** reveal actual HTTP(S) calls with response codes and timing.
* **Network flows** show all TCP/UDP connections including non-HTTP traffic.
* **Security events** highlight unusual or policy-violating outbound connections.

This comprehensive approach gives you both static configuration analysis and real-time traffic visibility for complete outbound connection monitoring.