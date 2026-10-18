# Verklikker

Execute install commands and applications inside Docker in a disposable Linux VM, and preserve process, filesystem and network evidence. npm is the first preset; jobs accept arbitrary images, argument vectors and input files.

**Initial implementation; the complete VM path is not yet hardware-validated.** Service/storage integration, gateway tests, image builds and HTTPS mocks have been exercised. Linux VM execution, macOS/HVF, ARM64 and a 200-VM fleet remain acceptance work. See [verification](docs/verification.md).

## Included

- TypeScript CLI, API, worker, guest agent and validated job contract.
- Fresh QEMU VM and copy-on-write disk per run; Linux KVM or macOS HVF, native x64/ARM64. No direct-host or software-emulation fallback.
- Restricted Docker specimen with CPU, memory, PID, time, disk and evidence limits; pinned Tracee observer inside the VM.
- Raw syscall/kernel events, process identities, file captures, stdout/stderr, final filesystem/workspace/volume archives and external PCAP.
- Public/allowlist egress, protected-address blocking, DNS overrides, static HTTP(S) mocks and opt-in TLS interception.
- JSONL, normalized Parquet, checksums and manifests; PostgreSQL queue/leases and private S3-compatible evidence.
- Keycloak/OIDC accounts, scoped revocable API keys, tenant quotas and a console with event/process/file/network/coverage views.
- Compose development stack and Kubernetes/KEDA worker chart capped at 200 jobs. That setting is not a measured capacity result.

Execution and capture health are separate. `completed` means the command exited zero; `healthy` means enabled collectors finished without a reported failure/loss. Neither is a safety verdict or a guarantee to observe every interaction.

## Develop and start the service

Requires Node.js 24+ and Docker for the reference services.

```sh
npm ci
npm run check
npm test
npm run build
node scripts/configure.mjs
docker compose up -d --build
```

Open <http://localhost:3000>. Configuration writes random credentials to `.env` with mode `0600` and refuses to overwrite an existing file. In the Keycloak console at <http://localhost:8080>, sign in as `admin` using `KEYCLOAK_ADMIN_PASSWORD` from `.env`, then create an ordinary user in the `verklikker` realm. Each OIDC subject receives an independent account. Public registration is disabled.

Compose binds loopback ports only: API `3000`, identity `8080`, S3 `8333`, PostgreSQL `54321`. It has no executor; run a native worker on a virtualization-capable host. Initial account limits are four concurrent jobs and 100 GiB storage; operators can change the `tenants` table. The Vite development server is available through `npm run web`; configure `PUBLIC_URL` and the identity redirect to match that port, or serve the built console through the API.

## Build and run the execution runtime

Image construction requires Docker/BuildKit. Execution uses native QEMU and does not use the host Docker daemon. Build on the intended native architecture.

| Host                      | Execution dependencies                                       |
| ------------------------- | ------------------------------------------------------------ |
| Linux x64/ARM64           | Accessible `/dev/kvm`, native QEMU system binary, `qemu-img` |
| macOS Intel/Apple silicon | Native QEMU with HVF, `qemu-img`                             |

Gateway construction requires Go 1.26.9, Python 3 and Git. TLS interception/mocks require `mitmdump` 12.2.1 in PATH (or the supplied worker image).

```sh
bash scripts/build-gateway.sh
bash scripts/build-guest.sh
npm run cli -- doctor
npm run cli -- run examples/observe.yaml
npm run cli -- npm is-number@7.0.0
```

The guest recipe embeds the base/npm images and Tracee 0.24.1 pinned by multi-architecture digest. `runtime/<arch>/manifest.json` records provenance and disk/kernel/initrd hashes. An operator may override `TRACEE_IMAGE` with another digest after verifying its collector flags. The gateway uses a pinned gvisor-tap-vsock commit and checked policy patches.

Local evidence is in `artifacts/<run-id>/`. Files use opaque UUIDs; `manifest.json` maps descriptive names and checksums. Nothing is automatically extracted or executed on the host. The base guest disk is 8 GiB, expanding to 20 GiB by default. Guest filesystem exports also consume this disk during collection.

## Remote CLI and workers

Create an API key in the console, or use device login:

```sh
export VERKLIKKER_URL=http://localhost:3000
npm run cli -- login
npm run cli -- submit examples/npm.yaml --idempotency-key npm-probe-1
npm run cli -- status RUN_ID --wait
npm run cli -- download RUN_ID ./evidence
npm run cli -- cancel RUN_ID
npm run cli -- delete RUN_ID
```

CI supplies `VERKLIKKER_TOKEN` as a secret. `batch` accepts a YAML array of up to 1,000 specifications per request and returns individual results. The queue holds up to 5,000 pending jobs per account. `POST /v1/runs/status` returns up to 5,000 statuses in one snapshot. OpenAPI is at `/openapi.json`.

On an executor host, set `API_URL`, `WORKER_TOKEN`, `S3_PUBLIC_ENDPOINT` and optionally `RUNTIME_DIRECTORY`, then run `npm run worker`. The worker token is a control-plane credential and never enters specimens. Workers use object-specific signed S3 URLs, without bucket-wide credentials.

Default worker capacity is 2 CPUs, 4 GiB RAM, 20 GiB disk and 10 GiB evidence. Configure `WORKER_CPUS`, `WORKER_MEMORY_MIB`, `WORKER_DISK_BYTES`, `WORKER_EVIDENCE_BYTES` for larger pools; incompatible jobs stay queued. Workers heartbeat every three seconds, stop on local lease expiry, and report against attempt-specific tokens. Expired jobs become `interrupted` and are not silently retried. Local evidence is removed after successful remote finalization unless `KEEP_LOCAL_EVIDENCE=1`.

## Inputs and networking

`npm run cli -- upload ./script.js` returns an input UUID. Use it in a job:

```yaml
image: verklikker/npm:local
argv: [node, /work/script.js]
inputs:
  - artifactId: YOUR_INPUT_UUID
    path: /work/script.js
```

Local runs accept `--input UUID=./script.js`; remote inputs must belong to the submitting account. Each input is at most 64 MiB, and destination parent directories must exist. Commands are argument vectors; request `bash -lc` explicitly for shell syntax. Keep PID 1 alive for runtime observation: Docker ends the container when its main process exits.

[examples/mock.yaml](examples/mock.yaml) demonstrates a local HTTPS response. Rules are ordered. `*.example.com` matches subdomains, not the apex. DNS answers support A/AAAA. ICMP is captured but not forwarded. Direct external DNS/DoT is denied; public HTTPS may still carry encrypted DNS or other opaque traffic.

Private, loopback, link-local, multicast, reserved, metadata, host-interface and known controller/storage destinations are denied even when allow rules name them. Mocks can respond locally without dialing that destination. Interception adds temporary CA trust and can change behavior; certificate pinning/custom trust stores can prevent decryption. Domain rules for raw TCP/UDP use observed DNS-to-IP associations, so shared hosting/CDNs can be ambiguous. They are not strict application-hostname isolation.

## Kubernetes

Build/push service and native worker images:

```sh
docker build -t verklikker/service:0.1.0 .
docker build -f images/worker.Dockerfile --build-arg RUNTIME_ARCH=x64 -t verklikker/worker:0.1.0 .
```

Install KEDA and an administrator-managed KVM device plugin exposing `squat.ai/kvm` on dedicated executor nodes. Set the actual device group in `worker.kvmGroup`, and label nodes `verklikker.io/executor=true`. Workers are unprivileged and have no Docker socket. Node seccomp/device configuration must permit QEMU's required KVM ioctls.

Create the existing Secret described in [values.yaml](deploy/helm/values.yaml), then install:

```sh
helm upgrade --install verklikker deploy/helm \
  --set serviceImage=YOUR_REGISTRY/verklikker-service:0.1.0 \
  --set workerImage=YOUR_REGISTRY/verklikker-worker:0.1.0
```

Supply PostgreSQL, private S3, identity, TLS ingress, backups and node autoscaling for your site. The chart does not provision a cloud cluster. The bundled OIDC adapter uses Keycloak endpoint paths. Every worker/browser must reach `S3_PUBLIC_ENDPOINT`; internal API storage access uses `S3_ENDPOINT`.

At default resource requests, 200 workers need roughly 600 CPUs, 1,200 GiB RAM and 8,000 GiB ephemeral disk across the fleet, before service capacity and headroom. Account concurrency/storage quotas must permit the test. See [capacity verification](docs/verification.md).

## Retention and coverage

Evidence stays until explicitly deleted. Active runs must first be cancelled. Object deletion is delayed beyond signed URL expiry and retried through a database outbox; abandoned uploads are collected. Keep buckets private and configure encryption/backups for your environment.

Online queries are limited to 512 MiB Parquet per run, four concurrent queries per API process, 256 MiB DuckDB memory and ten seconds of query execution. Download larger evidence for offline analysis. Logs, archives and packet payloads remain untrusted data.

Read [architecture](docs/architecture.md) for trust boundaries and blind spots and [verification](docs/verification.md) for remaining release gates.
