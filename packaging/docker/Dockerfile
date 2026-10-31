# The dashboard image, built from source. It only uses classic Dockerfile
# features, so it builds with or without BuildKit, for example on Dokploy.
#
#   docker build -f packaging/docker/Dockerfile --build-arg VERSION=v0.1.0 .

FROM golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=${VERSION}" \
		-o /out/usr/bin/bestbefore ./cmd/bestbefore \
	&& mkdir -p /out/var/lib/bestbefore \
	&& chmod 0700 /out/var/lib/bestbefore

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

COPY --from=build /out/usr/bin/bestbefore /usr/bin/bestbefore
# Copying the parent keeps the data folder's own mode, 0700.
COPY --from=build --chown=nonroot:nonroot /out/var/lib/ /var/lib/
COPY packaging/docker/dashboard.conf /etc/bestbefore/dashboard.conf

USER nonroot
VOLUME /var/lib/bestbefore
EXPOSE 8443
ENTRYPOINT ["/usr/bin/bestbefore"]
CMD ["--config", "/etc/bestbefore/dashboard.conf"]
