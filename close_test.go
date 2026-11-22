package bitlocker

import (
	"bytes"
	"testing"
)

// Close must wipe the sector key and drop the cipher holding its expanded form.
func TestCloseWipesSectorKey(t *testing.T) {
	img, _ := buildImage(t, defaultSpec())
	d, err := open(t, img, "secret", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	key := d.key // the live slice: Close must zero it in place
	saved := bytes.Clone(key)
	if len(saved) == 0 || bytes.Equal(saved, make([]byte, len(saved))) {
		t.Fatalf("no key to observe: %d bytes", len(saved))
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatalf("after Close the Device still holds the %d-byte sector key", len(key))
	}
	if d.c != nil {
		t.Fatal("after Close the Device still holds its cipher")
	}
	if _, err := d.ReadAt(make([]byte, 16), 0); err == nil {
		t.Fatal("ReadAt after Close succeeded")
	}
}
