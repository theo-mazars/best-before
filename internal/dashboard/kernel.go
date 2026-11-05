package dashboard

import (
	"regexp"
	"strings"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/dashboard/vulns"
)

// abiPattern finds a kernel ABI, e.g. 6.8.0-60 in 6.8.0-60-generic or in
// linux-hwe-6.8-headers-6.8.0-60.
var abiPattern = regexp.MustCompile(`\d+\.\d+\.\d+-\d+`)

func kernelABI(s string) string { return abiPattern.FindString(s) }

// oldKernel says whether a finding is in a kernel package of another ABI
// than the running kernel's. Meta packages such as linux-image-generic name
// no ABI and are never old. Without a known running kernel, nothing is.
func oldKernel(f *store.Finding, running string) bool {
	if running == "" || f.Target != vulns.TargetHost || f.Kind != vulns.KindPackage || !strings.HasPrefix(f.Package, "linux-") {
		return false
	}
	abi := kernelABI(f.Package)
	return abi != "" && abi != running
}
