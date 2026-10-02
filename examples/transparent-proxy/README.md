# Transparent proxy

Transparent proxying on a local HTTPS listener: upstream discovery is
`transparent` (the original destination the kernel routed to this proxy),
SNI passes through as `$host`, and one default development certificate
serves every domain.

Traffic has to reach the listener first — an iptables REDIRECT or TPROXY
rule routing port 443 to the proxy's address.

```bash
sudo pingap-waf -c=examples/transparent-proxy/transparent-proxy.toml --admin=127.0.0.1:3018
```
