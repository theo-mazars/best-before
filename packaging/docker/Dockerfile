# The dashboard image, built from source. It only uses classic Dockerfile
# features, so it builds with or without BuildKit, for example on Dokploy.
#
#   docker build -f packaging/docker/Dockerfile --build-arg VERSION=v0.1.0 .
#
# See docs/dashboard.md for building it from a release.

FROM node:24.16.0-alpine3.24@sha256:21f403ab171f2dc89bad4dd69d7721bfd15f084ccb46cdd225f31f2bc59b5c9a AS ui

WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ui/.npmrc ./
RUN npm ci
COPY ui ./
ARG VERSION=dev
RUN VERSION=${VERSION} npm run build

FROM golang:1.26.11-alpine3.24@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=ui /src/internal/dashboard/webui/dist ./internal/dashboard/webui/dist

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=${VERSION}" \
		-o /out/usr/bin/bestbefore ./cmd/bestbefore \
	&& mkdir -p /out/var/lib/bestbefore \
	&& chmod 0700 /out/var/lib/bestbefore

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG VERSION=dev
LABEL org.opencontainers.image.title="Best Before dashboard" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.source="https://github.com/theo-mazars/best-before" \
	org.opencontainers.image.licenses="AGPL-3.0-only"

COPY LICENSE /usr/share/doc/bestbefore/LICENSE
COPY --from=build /out/usr/bin/bestbefore /usr/bin/bestbefore
# Copying the parent keeps the data folder's own mode, 0700.
COPY --from=build --chown=nonroot:nonroot /out/var/lib/ /var/lib/
COPY packaging/docker/dashboard.conf /etc/bestbefore/dashboard.conf

USER nonroot
VOLUME /var/lib/bestbefore
EXPOSE 8443
ENTRYPOINT ["/usr/bin/bestbefore"]
CMD ["--config", "/etc/bestbefore/dashboard.conf"]
