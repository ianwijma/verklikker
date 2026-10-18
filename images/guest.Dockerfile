FROM node:24-bookworm AS build
WORKDIR /source
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY packages packages
COPY apps/api apps/api
COPY apps/guest apps/guest
COPY apps/worker apps/worker
COPY apps/cli apps/cli
RUN npx tsc -p tsconfig.json && npm prune --omit=dev
FROM node:24-bookworm-slim AS guest
ARG TARGETARCH
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv docker.io initramfs-tools iproute2 isc-dhcp-client e2fsprogs ca-certificates kmod "linux-image-${TARGETARCH}" && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/dist /opt/verklikker/dist
COPY --from=build /source/node_modules /opt/verklikker/node_modules
COPY package.json /opt/verklikker/package.json
COPY runtime/build-inputs /opt/images
RUN cp /opt/images/tracee-image /opt/tracee-image
COPY images/guest-init.sh /opt/verklikker/init.sh
COPY images/verklikker.service /etc/systemd/system/verklikker.service
RUN chmod 755 /opt/verklikker/init.sh && systemctl enable verklikker.service
RUN mkdir -p /etc/docker && printf '%s\n' '{"log-driver":"local","log-opts":{"max-size":"10m","max-file":"2"},"ipv6":true,"fixed-cidr-v6":"fd00:7666::/64","ip6tables":true}' > /etc/docker/daemon.json
FROM debian:bookworm-slim AS disk
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs qemu-utils && rm -rf /var/lib/apt/lists/*
COPY --from=guest / /rootfs/
RUN mkdir /out && truncate -s 8G /disk.raw && mkfs.ext4 -q -F -d /rootfs /disk.raw && qemu-img convert -f raw -O qcow2 -c /disk.raw /out/rootfs.qcow2 && cp /rootfs/boot/vmlinuz-* /out/vmlinuz && cp /rootfs/boot/initrd.img-* /out/initrd
FROM scratch
COPY --from=disk /out/ /
