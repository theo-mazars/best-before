// Package version holds build metadata injected at link time.
package version

// Version is overridden at build time with
// -ldflags "-X github.com/theo-mazars/best-before/internal/version.Version=v1.2.3".
var Version = "dev"
