FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bash && rm -rf /var/lib/apt/lists/* && useradd -m -u 1000 investigator && mkdir /work && chown 1000:1000 /work
USER 1000:1000
WORKDIR /work
CMD ["bash"]
