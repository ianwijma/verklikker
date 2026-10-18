# Verification and acceptance

A mocked workload or scheduler claim is not proof that a real VM captured a specimen.

## Fast checks

```sh
npm ci
npm run check
npm test
npm run build
bash scripts/build-gateway.sh
bash scripts/test-gateway.sh
```

Tests cover protected IPv4/IPv6/mapped destinations, DNS expiry, mocks, gateway fail-closed decisions, connection/byte accounting, channel limits/closure, raw precision, heterogeneous Parquet and evidence budgets. Network-policy tests require permission to enumerate local network interfaces; do not weaken production protection to accommodate a restrictive test sandbox.

## Database and storage integration

Use a disposable database with no concurrent workers:

```sh
TEST_DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/TEST_DB npm run test:integration
```

For real S3 coverage, also supply `TEST_S3_ENDPOINT`, `TEST_S3_BUCKET`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Missing endpoints explicitly skip their suites. Tests create/remove their own fixtures. They exercise signed PUT/GET, artifact commit/query, cross-tenant input/download denial, concurrent claims, quotas/capacity, idempotency, cancellation, stale/expired leases, revocation and deletion.

## Full VM acceptance

```sh
bash scripts/build-guest.sh
npm run cli -- doctor
node --import tsx scripts/smoke-vm.ts
npm run cli -- run examples/mock.yaml
npm run cli -- run examples/npm.yaml
```

The smoke test calls the real runner and fails if hardware virtualization is absent. It checks process/read/write events and artifact classes. On every native OS/architecture also verify:

1. Fork/reparent/exit, rename/unlink, native binaries, `mmap`, `io_uring` and raw sockets against documented collector coverage.
2. Public IPv4/IPv6 and denial of metadata, LAN, loopback, host/control/storage, external DNS and DNS rebinding; inspect actual upstream connections.
3. HTTPS mocks with CA validation, ordinary passthrough, upstream certificate failure and pinning.
4. Collector/gateway/worker failure, lost control connectivity, event loss, disk-full, malformed frames and budget exhaustion; expect bounded teardown and incomplete partial evidence.
5. Cancellation during boot/execution/export; ensure no QEMU process, socket or overlay survives.
6. API/database restarts; ensure lease expiry is conservative and attempts are not silently repeated.

## Fleet acceptance

Provision KVM nodes and raise the test account's concurrency/storage quota deliberately. The chart's 200-worker ceiling is configuration, not a successful capacity test.

```sh
VERKLIKKER_URL=https://YOUR_SERVICE VERKLIKKER_TOKEN=YOUR_TEST_KEY \
JOBS=1000 TARGET_CONCURRENCY=200 node --import tsx scripts/load-test.ts
```

This submits real 60-second benign jobs, measures simultaneous `running` states from one database snapshot, excludes boot/collection, and requires healthy completion. It writes `capacity-result.json` and fails when the target is not met. Evidence remains for inspection and explicit deletion.

Also test mixed tenants/sizes, exhausted quotas, node loss, partial S3 failures and sustained ingress. Track startup/query latency, event loss and CPU/RAM/disk/storage pressure. Authenticated `/internal/metrics` exposes run/tenant/active/storage gauges.

## Initial validation boundary

Checked on Linux x64: TypeScript/unit tests, PostgreSQL integration, real S3 signed-upload/query integration, native gateway tests, guest/service/worker image builds and HTTPS mocking with CA verification. The reference UI and identity flow were exercised locally. Full guest execution is blocked by absent `/dev/kvm`; macOS/HVF, ARM64 and the 200-VM fleet remain unverified. These are release gates for hostile specimens.
