package testutils

import (
	"errors"
	"testing"

	"github.com/DataDog/ebpf/internal"
)

func CheckFeatureTest(t *testing.T, fn func() error) {
	t.Helper()

	err := fn()
	if err == nil {
		return
	}

	ufe := err.(*internal.UnsupportedFeatureError)
	checkKernelVersion(t, ufe)
}

func SkipIfNotSupported(tb testing.TB, err error) {
	var ufe *internal.UnsupportedFeatureError
	if errors.As(err, &ufe) {
		checkKernelVersion(tb, ufe)
		tb.Skip(ufe.Error())
	}
}

func checkKernelVersion(tb testing.TB, ufe *internal.UnsupportedFeatureError) {
	kernelVersion := internal.MustKernelVersion()
	if ufe.MinimumVersion.Less(kernelVersion) {
		tb.Helper()
		tb.Fatalf("Feature '%s' isn't supported even though kernel %s is newer than %s",
			ufe.Name, kernelVersion, ufe.MinimumVersion)
	}
}

func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	minv, err := internal.NewVersion(minVersion)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", minVersion, err)
	}

	if internal.MustKernelVersion().Less(minv) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minv, feature)
	}
}
