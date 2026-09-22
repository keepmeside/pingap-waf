# Docker deployment

The supported container deployment uses `docker compose`. It publishes only the
public data plane on ports 80 and 443. The admin listener is bound to loopback
by default (`127.0.0.1:3018`) and etcd is on an internal-only network.

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
The pull overlay is intentionally limited to the loopback admin port and does
not publish metrics or etcd.
