package bitlocker

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

// fuzzSpec is the smallest layout the builder writes: three metadata areas
// and the header copy in 320 KiB, and protectors that need no key
// derivation, so that one execution takes microseconds.
func fuzzSpec(p protSpec) imageSpec {
	s := defaultSpec()
	s.size = 320 << 10
	s.metaOffs = [3]uint64{64 << 10, 128 << 10, 192 << 10}
	s.hdrOff = 256 << 10
	s.protectors = []protSpec{p}
	return s
}

var fuzzBEK = bytes.Repeat([]byte{0x42}, 32)

func fuzzSeeds(f *testing.F) [][]byte {
	clearImg, _ := buildImage(f, fuzzSpec(protSpec{prot: ClearKey, guid: [16]byte{4}, clearKey: bytes.Repeat([]byte{0x24}, 32)}))
	bekImg, _ := buildImage(f, fuzzSpec(protSpec{prot: StartupKey, guid: [16]byte{5}, bekKey: fuzzBEK}))
	s := fuzzSpec(protSpec{prot: ClearKey, guid: [16]byte{4}, clearKey: bytes.Repeat([]byte{0x24}, 32)})
	s.method, s.sectorSize, s.togo = AES256CBC, 4096, true
	cbcImg, _ := buildImage(f, s)
	return [][]byte{clearImg, bekImg, cbcImg}
}

// FuzzOpen opens mutated volumes with a clear key or a startup key and
// reads them: any input may be refused, none may panic, hang or read past
// what it declares.
func FuzzOpen(f *testing.F) {
	bek := bekFile(fuzzBEK, [16]byte{5}, defaultSpec().volGUID, true)
	for _, img := range fuzzSeeds(f) {
		f.Add(img, bek)
	}
	f.Fuzz(func(t *testing.T, img, secret []byte) {
		if len(img) > 1<<20 {
			return
		}
		// The fuzzer has no per-input timeout: a hang would stall its
		// workers without naming the input. Crashing records it.
		timer := time.AfterFunc(10*time.Second, func() { panic("one input took over 10 s") })
		defer timer.Stop()
		d, err := OpenFrom(memDev{bytes.NewReader(img)}, int64(len(img)), secret, Limits{MaxKeyDerivations: 0})
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrNotBitLocker) &&
				!errors.Is(err, ErrWrongSecret) && !errors.Is(err, ErrLimit) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if d.Size() > int64(len(img)) {
			t.Fatalf("size %d of a %d-byte device", d.Size(), len(img))
		}
		if _, err := io.Copy(io.Discard, io.NewSectionReader(d, 0, d.Size())); err != nil {
			t.Fatalf("read: %v", err)
		}
	})
}

// FuzzStartupKey parses mutated .BEK files.
func FuzzStartupKey(f *testing.F) {
	vmk, vol := [16]byte{5}, defaultSpec().volGUID
	f.Add(bekFile(fuzzBEK, vmk, vol, true))
	f.Add(bekFile(fuzzBEK, vmk, vol, false))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, ok, err := startupKey(b, formatGUID(vmk[:]), formatGUID(vol[:]))
		if err == nil && ok && k == nil {
			t.Fatal("accepted without a key")
		}
	})
}

// FuzzRecoveryPassword checks that only the 55-character shape is taken.
func FuzzRecoveryPassword(f *testing.F) {
	f.Add([]byte(testRecovery))
	f.Add([]byte(testRecovery + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, ok := recoveryInitial(b); ok && len(b) != recoveryLen && len(b) != recoveryLen+1 {
			t.Fatalf("accepted %d bytes", len(b))
		}
	})
}
