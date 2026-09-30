# Docker deployment

The supported container deployment uses `docker compose`. It publishes only the
public data plane on ports 80 and 443. The admin listener binds the internal
`control` network's pinned address (`172.30.0.10:3018`) — reachable from the host
(and over an SSH tunnel to it) at that address, and absent from the public
data-plane network entirely. etcd is on the same internal-only network.

## First install

Set a non-default bootstrap password in the shell, then run:

```sh
export PINGAP_ADMIN_PASSWORD='use-a-password-manager-generated-value'
./scripts/install-docker.sh
```

The script writes `.env` with mode `0600` and starts the image build. Do not put
credentials in the compose file, image, or a shell command committed to source.
The first successful admin bootstrap creates the account; retain the `.env` file
outside source control and rotate the password after first login.

For local development, use `docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build`.
The dev and pull overlays re-bind admin to `127.0.0.1:3018` and publish it on
loopback for a single-machine setup — a deliberate convenience for a host that is
not the production posture; the production `docker-compose.yml` keeps admin on the
internal control network instead. Neither overlay publishes metrics or etcd.
