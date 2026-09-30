# Security posture

The compose deployment exposes only the customer data plane on TCP 80 and 443.
The admin API and UI bind the internal `control` network's pinned address
(`172.30.0.10:3018`), **not** a wildcard — so the listener is absent from the
public data-plane network entirely, not merely unpublished. The host (and an
operator reaching it over SSH) reaches admin at `http://172.30.0.10:3018`; a
host port-publish is deliberately absent because Docker would forward it to the
container's public interface, where admin does not listen. Operators should
reach it over an authenticated SSH tunnel or an operator-only network; it is
not a public endpoint.

Metrics use push mode when configured. No metrics path is configured on the
public server by the packaged compose deployment, so `/metrics` is not an
unauthenticated public endpoint — `tests/exposure/scan.sh` asserts the fetch
fails. etcd has no host port mapping and lives on the `control` network, marked
`internal: true`. Store and backup volumes are mounted outside the served
configuration tree and the scan asserts neither is fetchable over HTTP.

The inherited deployment used wildcard admin and metrics listeners and embedded
a default password. This deployment requires `PINGAP_ADMIN_PASSWORD` at install
time, never bakes it into the image, and keeps it out of compose logs. Exposure
must be checked from outside the deployment with `tests/exposure/scan.sh`.
