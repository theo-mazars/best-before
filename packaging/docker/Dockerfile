# The dashboard image. It packages the binary built by `make build-linux`, so
# the image contains exactly the binary that is released and signed.
#
#   make image

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG TARGETARCH
COPY --chmod=0555 bin/linux-${TARGETARCH}/bestbefore /usr/bin/bestbefore
COPY packaging/docker/dashboard.conf /etc/bestbefore/dashboard.conf
COPY --chown=nonroot:nonroot --chmod=0700 packaging/docker/data/ /var/lib/bestbefore/

USER nonroot
VOLUME /var/lib/bestbefore
EXPOSE 8443
ENTRYPOINT ["/usr/bin/bestbefore"]
CMD ["--config", "/etc/bestbefore/dashboard.conf"]
