package bitlocker

import (
	"compress/gzip"
	"os"
	"testing"
)

// fixtureEnv names where TestWriteFixture writes a small password-protected
// volume, gzipped, for packages that stack on this one (go-fde/fde) and
// cannot use this package's test writer. Password "fde", AES-XTS-128,
// 264 KiB.
const fixtureEnv = "BITLK_WRITE_FIXTURE"

func TestWriteFixture(t *testing.T) {
	path := os.Getenv(fixtureEnv)
	if path == "" {
		t.Skipf("%s is not set", fixtureEnv)
	}
	s := defaultSpec()
	s.size = 264 << 10
	s.metaOffs = [3]uint64{64 << 10, 128 << 10, 192 << 10}
	s.hdrOff = 256 << 10
	s.protectors = []protSpec{{prot: Password, guid: [16]byte{1}, password: "fde"}}
	img, plain := buildImage(t, s)
	d, err := open(t, img, "fde", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustReadAll(t, d); string(got) != string(plain) {
		t.Fatal("the fixture does not read back")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(img); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
