# Third-party components

The gateway build fetches [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) at the commit pinned in `scripts/build-gateway.sh`, applies `native/gateway/prepare.py`, and links its Go dependencies including gVisor. Retain upstream license/notice files when distributing binaries or images.

Guest images include Debian, Node.js, Docker and [Tracee](https://github.com/aquasecurity/tracee). Interception uses [mitmproxy](https://github.com/mitmproxy/mitmproxy). Reference services use PostgreSQL, Keycloak and SeaweedFS. JavaScript dependency versions are in `package-lock.json`.

This inventory does not replace component licenses or assign a license to the project's original source.
