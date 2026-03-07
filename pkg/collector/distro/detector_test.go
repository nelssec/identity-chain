package distro

import (
	"context"
	"testing"
)

func TestGenericDetector(t *testing.T) {
	d := &GenericDetector{}
	profile, err := d.Detect(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Platform != "kubernetes" {
		t.Errorf("expected platform 'kubernetes', got %q", profile.Platform)
	}
	if profile.CloudProvider != "unknown" {
		t.Errorf("expected cloud provider 'unknown', got %q", profile.CloudProvider)
	}
	if len(profile.SystemNamespacePrefixes) == 0 {
		t.Error("expected non-empty system namespace prefixes")
	}
}
