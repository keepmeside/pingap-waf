# Security posture

The compose deployment exposes only the customer data plane on TCP 80 and 443.
The admin API and UI bind to `127.0.0.1:3018` and require the configured admin
credentials. Operators should place the admin port behind an authenticated SSH
tunnel or an operator-only network; it is not a public endpoint.

Metrics use push mode when configured. No metrics path is configured on the
public server by the packaged compose deployment, so `/metrics` is not an
unauthenticated public endpoint. etcd has no host port mapping and is attached
to an internal Docker network. Store and backup volumes are mounted outside the
served configuration tree and are not published as HTTP paths.

The inherited deployment used wildcard admin and metrics listeners and embedded
a default password. This deployment requires `PINGAP_ADMIN_PASSWORD` at install
time, never bakes it into the image, and keeps it out of compose logs. Exposure
must be checked from outside the deployment with `tests/exposure/scan.sh`.
