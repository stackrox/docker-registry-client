package registry

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

var (
	fakeDigest = digest.FromString("sha256:0000000000000000000000000000000000000000000000000000000000000000")
)

func newHandlerFunc(mediaType string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "emptyheader") {
			w.Header().Add("Docker-Content-Digest", "")
		}

		if strings.Contains(r.URL.Path, "invalidheader") {
			w.Header().Add("Docker-Content-Digest", "invaliddigest")
		}

		if strings.Contains(r.URL.Path, "validheader") {
			w.Header().Add("Docker-Content-Digest", string(fakeDigest))
		}

		w.Write([]byte(fmt.Sprintf(`{"mediaType":"%s"}`, mediaType)))
	})
}

func TestManifestV2WithDigest(t *testing.T) {
	mediaType := "application/vnd.docker.distribution.manifest.v2+json"
	s := httptest.NewServer(newHandlerFunc(mediaType))
	t.Cleanup(s.Close)

	r, err := NewInsecure(s.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, digest, err := r.ManifestV2WithDigest("noheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestV2WithDigest("emptyheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestV2WithDigest("invalidheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestV2WithDigest("validheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != fakeDigest {
		t.Errorf("Expected digest %q but got: %q", fakeDigest, digest)
	}
}

func TestManifestOCIWithDigest(t *testing.T) {
	mediaType := "application/vnd.oci.image.manifest.v1+json"
	s := httptest.NewServer(newHandlerFunc(mediaType))
	t.Cleanup(s.Close)

	r, err := NewInsecure(s.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, digest, err := r.ManifestOCIWithDigest("noheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestOCIWithDigest("emptyheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestOCIWithDigest("invalidheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != "" {
		t.Errorf("Expected empty digest but got: %q", digest)
	}

	_, digest, err = r.ManifestOCIWithDigest("validheader", "tag")
	if err != nil {
		t.Error(err)
	}
	if digest != fakeDigest {
		t.Errorf("Expected digest %q but got: %q", fakeDigest, digest)
	}
}
