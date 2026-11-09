package bitlocker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T, img []byte, secret string, lim Limits) (*Device, error) {
	t.Helper()
	var s []byte
	if secret != "" {
		s = []byte(secret)
	}
	return OpenFrom(memDev{bytes.NewReader(img)}, int64(len(img)), s, lim)
}

func mustReadAll(t *testing.T, d *Device) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(d, 0, d.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const testRecovery = "000011-000022-000033-000044-000055-000066-000077-000088"

func TestRoundTrip(t *testing.T) {
	bek := bytes.Repeat([]byte{0x42}, 32)
	clearK := bytes.Repeat([]byte{0x24}, 32)
	cases := []struct {
		name   string
		spec   func(*imageSpec)
		secret string
	}{
		{"xts-128 password", func(*imageSpec) {}, "secret"},
		{"xts-256", func(s *imageSpec) { s.method = AES256XTS }, "secret"},
		{"cbc-128", func(s *imageSpec) { s.method = AES128CBC }, "secret"},
		{"cbc-256", func(s *imageSpec) { s.method = AES256CBC }, "secret"},
		{"4k sectors", func(s *imageSpec) { s.sectorSize = 4096 }, "secret"},
		{"to go", func(s *imageSpec) { s.togo = true }, "secret"},
		{"recovery password", func(s *imageSpec) {
			s.protectors = []protSpec{{prot: RecoveryPassword, guid: [16]byte{2}, password: testRecovery}}
		}, testRecovery + "\n"},
		{"second protector", func(s *imageSpec) {
			s.protectors = []protSpec{
				{prot: TPM, guid: [16]byte{9}},
				{prot: Password, guid: [16]byte{1}, password: "other"},
				{prot: Password, guid: [16]byte{3}, password: "secret"},
			}
		}, "secret"},
		{"clear key", func(s *imageSpec) {
			s.protectors = []protSpec{{prot: ClearKey, guid: [16]byte{4}, clearKey: clearK}}
		}, ""},
		{"startup key", func(s *imageSpec) {
			s.protectors = []protSpec{{prot: StartupKey, guid: [16]byte{5}, bekKey: bek}}
		}, string(bekFile(bek, [16]byte{5}, defaultSpec().volGUID, true))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := defaultSpec()
			c.spec(&s)
			img, plain := buildImage(t, s)
			d, err := open(t, img, c.secret, DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if d.Size() != int64(len(plain)) {
				t.Fatalf("size %d, want %d", d.Size(), len(plain))
			}
			if got := mustReadAll(t, d); !bytes.Equal(got, plain) {
				t.Fatalf("decrypted device differs at %d", firstDiff(got, plain))
			}
			if d.Info().Description != "DESK" {
				t.Errorf("description %q", d.Info().Description)
			}
		})
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func bekFile(key []byte, vmk, vol [16]byte, withGUID bool) []byte {
	var nested []byte
	nested = append(nested, mkEntry(entryProperty, valueString, []byte{'E', 0})...)
	if withGUID {
		nested = append(nested, mkEntry(entryVolumeGUID, valueGUID, vol[:])...)
	}
	nested = append(nested, mkEntry(entryProperty, valueKey, append(make([]byte, 4), key...))...)
	e := mkEntry(entryStartupKey, valueExternalKey, append(make([]byte, startupKeyHeaderLen), nested...))
	h := make([]byte, bekHeaderLen)
	binary.LittleEndian.PutUint32(h, uint32(bekHeaderLen+len(e)))
	binary.LittleEndian.PutUint32(h[4:], 1)
	copy(h[16:], vmk[:])
	return append(h, e...)
}

func TestReadAtEdges(t *testing.T) {
	img, plain := buildImage(t, defaultSpec())
	d, err := open(t, img, "secret", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("negative offset read")
	}
	if n, err := d.ReadAt(make([]byte, 1), d.Size()); n != 0 || err != io.EOF {
		t.Errorf("at the end: %d %v", n, err)
	}
	// unaligned, across the header copy, a zero area and identity sectors
	for _, r := range [][2]int{{3, 9000}, {(64 << 10) - 7, 300}, {(448 << 10) - 100, 9000}, {len(plain) - 10, 10}} {
		b := make([]byte, r[1])
		n, err := d.ReadAt(b, int64(r[0]))
		if err != nil || n != r[1] || !bytes.Equal(b, plain[r[0]:r[0]+r[1]]) {
			t.Errorf("ReadAt(%d, %d): %d %v, differs at %d", r[0], r[1], n, err, firstDiff(b, plain[r[0]:]))
		}
	}
	b := make([]byte, 20)
	if n, err := d.ReadAt(b, d.Size()-10); n != 10 || err != io.EOF || !bytes.Equal(b[:10], plain[len(plain)-10:]) {
		t.Errorf("past the end: %d %v", n, err)
	}
	if _, err := d.WriteAt(b, 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("WriteAt: %v", err)
	}
	// a short underlying device
	short := memDev{bytes.NewReader(img[:len(img)-512])}
	d2 := *d
	d2.r = short
	if _, err := d2.ReadAt(make([]byte, 512), d.Size()-512); err == nil {
		t.Error("read past a truncated device")
	}
}

func TestOpenFile(t *testing.T) {
	img, plain := buildImage(t, defaultSpec())
	path := filepath.Join(t.TempDir(), "v.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got := mustReadAll(t, d); !bytes.Equal(got, plain) {
		t.Error("file read differs")
	}
	if err := d.Close(); err != nil {
		t.Error(err)
	}
	if _, err := Open(path, []byte("wrong")); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("missing file opened")
	}
	if _, err := Open(t.TempDir(), nil); err == nil {
		t.Error("a directory opened")
	}
}

func TestDetect(t *testing.T) {
	img, _ := buildImage(t, defaultSpec())
	if !Detect(bytes.NewReader(img)) {
		t.Error("BitLocker not detected")
	}
	s := defaultSpec()
	s.togo = true
	togo, _ := buildImage(t, s)
	if !Detect(bytes.NewReader(togo)) {
		t.Error("To Go not detected")
	}
	fat := append([]byte(nil), togo[:512]...)
	clear(fat[superblockOffToGo : superblockOffToGo+16])
	if Detect(bytes.NewReader(fat)) {
		t.Error("a FAT32 volume detected as To Go")
	}
	if Detect(bytes.NewReader(img[:100])) {
		t.Error("a short device detected")
	}
	plain := make([]byte, 512)
	if Detect(bytes.NewReader(plain)) {
		t.Error("zeros detected")
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name   string
		spec   func(*imageSpec)
		img    func([]byte) []byte
		secret string
		want   error
		text   string
	}{
		{name: "not bitlocker", img: func(b []byte) []byte { b[3] = 'X'; return b }, want: ErrNotBitLocker},
		{name: "empty", img: func(b []byte) []byte { return b[:0] }, want: ErrNotBitLocker},
		{name: "vista", img: func(b []byte) []byte { b[1] = 0x52; return b }, want: ErrUnsupported},
		{name: "boot code", img: func(b []byte) []byte { b[0] = 0; return b }, want: ErrCorrupt},
		{name: "sector size", img: func(b []byte) []byte { b[11], b[12] = 0, 4; return b }, want: ErrCorrupt},
		{name: "every CRC", img: func(b []byte) []byte {
			for _, o := range defaultSpec().metaOffs {
				b[o+200]++
			}
			return b
		}, want: ErrCorrupt, text: "CRC-32"},
		{name: "metadata past the device", img: func(b []byte) []byte {
			binary.LittleEndian.PutUint64(b[superblockOff+16:], 1<<40)
			binary.LittleEndian.PutUint64(b[superblockOff+24:], 1<<40)
			binary.LittleEndian.PutUint64(b[superblockOff+32:], 1<<40)
			return b
		}, want: ErrCorrupt},
		{name: "copy elsewhere than it says", img: func(b []byte) []byte {
			// the volume header points at copy 2 only, from slot 0
			binary.LittleEndian.PutUint64(b[superblockOff+16:], 192<<10)
			return b
		}, want: ErrCorrupt, text: "its own offset"},
		{name: "metadata version", spec: func(s *imageSpec) {
			s.mutate = func(b []byte) []byte { b[10] = 1; return b }
		}, want: ErrCorrupt},
		{name: "block size", spec: func(s *imageSpec) {
			s.mutate = func(b []byte) []byte { return append(b, make([]byte, 70000)...) }
		}, want: ErrCorrupt},
		{name: "validation version", img: func(b []byte) []byte {
			for _, o := range defaultSpec().metaOffs {
				n := int(binary.LittleEndian.Uint16(b[o+8:])) << 4
				b[int(o)+n+2] = 9
			}
			return b
		}, want: ErrCorrupt},
		{name: "validation record", img: func(b []byte) []byte {
			for _, o := range defaultSpec().metaOffs {
				n := int(binary.LittleEndian.Uint16(b[o+8:])) << 4
				b[int(o)+n+12] = 9
			}
			return b
		}, want: ErrCorrupt, text: "validation record"},
		{name: "method", spec: func(s *imageSpec) { s.method = 0x8009 }, want: ErrUnsupported},
		{name: "metadata size", spec: func(s *imageSpec) {
			s.mutate = func(b []byte) []byte { binary.LittleEndian.PutUint32(b[blockHeaderLen:], 1<<20); return b }
		}, want: ErrCorrupt, text: "metadata size"},
		{name: "entry overrun", spec: func(s *imageSpec) {
			s.mutate = func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[blockHeaderLen+metadataHeaderLen:], 0xfff0)
				return b
			}
		}, want: ErrCorrupt, text: "metadata entry"},
		{name: "no volume key", spec: func(s *imageSpec) { s.noFVEK = true }, want: ErrCorrupt, text: "no encrypted volume key"},
		{name: "no header entry", spec: func(s *imageSpec) { s.noHeader = true }, want: ErrCorrupt, text: "volume header entry"},
		{name: "encrypt on write", spec: func(s *imageSpec) { s.kindGUID = guidEOW }, want: ErrUnsupported},
		{name: "unknown kind", spec: func(s *imageSpec) { s.kindGUID = [16]byte{1} }, want: ErrUnsupported},
		{name: "being converted", spec: func(s *imageSpec) { s.state = 2 }, want: ErrUnsupported},
		{name: "header past the device", spec: func(s *imageSpec) { s.hdrOff = 1 << 30 }, want: ErrCorrupt, text: "outside"},
		{name: "header unaligned", spec: func(s *imageSpec) { s.hdrSize = 1000 }, want: ErrCorrupt, text: "outside"},
		{name: "regions overlap", spec: func(s *imageSpec) { s.hdrOff = 64 << 10 }, want: ErrCorrupt, text: "overlap"},
		{name: "wrong password", secret: "nope", want: ErrWrongSecret},
		{name: "nil secret", want: ErrWrongSecret, text: "password"},
		{name: "not a recovery password", spec: func(s *imageSpec) {
			s.protectors = []protSpec{{prot: RecoveryPassword, guid: [16]byte{2}, password: testRecovery}}
		}, secret: "secret", want: ErrWrongSecret, text: "recovery password"},
		{name: "wrong recovery password", spec: func(s *imageSpec) {
			s.protectors = []protSpec{{prot: RecoveryPassword, guid: [16]byte{2}, password: testRecovery}}
		}, secret: "000011-000022-000033-000044-000055-000066-000077-000099", want: ErrWrongSecret},
		{name: "tampered metadata", spec: func(s *imageSpec) {
			s.mutateSealed = func(b []byte) { b[blockHeaderLen+metadataHeaderLen-1] ^= 1 }
		}, secret: "secret", want: ErrCorrupt, text: "SHA-256"},
		{name: "volume master key size", spec: func(s *imageSpec) { s.vmkLen = 16 }, secret: "secret", want: ErrCorrupt, text: "master key of 16"},
		{name: "short volume key", spec: func(s *imageSpec) { s.fvekLen = 8 }, secret: "secret", want: ErrCorrupt, text: "volume key of 8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := defaultSpec()
			if c.spec != nil {
				c.spec(&s)
			}
			img, _ := buildImage(t, s)
			if c.img != nil {
				img = c.img(img)
			}
			_, err := open(t, img, c.secret, DefaultLimits)
			if !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			if c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Fatalf("%q does not say %q", err, c.text)
			}
		})
	}
}

// TestSecondCopy: a first metadata copy that fails its CRC-32 is skipped
// for the next one.
func TestSecondCopy(t *testing.T) {
	img, plain := buildImage(t, defaultSpec())
	img[(64<<10)+200]++
	d, err := open(t, img, "secret", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadAll(t, d), plain) {
		t.Error("differs")
	}
}

// TestKeyDerivationLimit is the bomb: protectors past the limit are not
// derived, and the refusal says so.
func TestKeyDerivationLimit(t *testing.T) {
	s := defaultSpec()
	s.protectors = []protSpec{
		{prot: Password, guid: [16]byte{1}, password: "a"},
		{prot: Password, guid: [16]byte{2}, password: "b"},
		{prot: Password, guid: [16]byte{3}, password: "secret"},
	}
	img, _ := buildImage(t, s)
	if _, err := open(t, img, "secret", Limits{MaxKeyDerivations: 2}); !errors.Is(err, ErrLimit) {
		t.Fatalf("%v, want ErrLimit", err)
	}
	if _, err := open(t, img, "secret", Limits{MaxKeyDerivations: 3}); err != nil {
		t.Fatal(err)
	}
}

func TestStartupKeyFile(t *testing.T) {
	bek := bytes.Repeat([]byte{0x42}, 32)
	vmk := [16]byte{5}
	vol := defaultSpec().volGUID
	good := bekFile(bek, vmk, vol, true)
	k, ok, err := startupKey(good, formatGUID(vmk[:]), formatGUID(vol[:]))
	if err != nil || !ok || !bytes.Equal(k, bek) {
		t.Fatalf("%x %v %v", k, ok, err)
	}
	noGUID := bekFile(bek, vmk, vol, false)
	if _, _, err := startupKey(noGUID, formatGUID(vmk[:]), formatGUID(vol[:])); err != nil {
		t.Errorf("without volume GUID: %v", err)
	}
	mod := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := []struct {
		name string
		b    []byte
		ok   bool
		want error
	}{
		{"short", good[:20], false, nil},
		{"other protector", mod(func(b []byte) []byte { b[16]++; return b }), false, nil},
		{"version", mod(func(b []byte) []byte { b[4] = 2; return b }), true, ErrUnsupported},
		{"size", mod(func(b []byte) []byte { b[0]++; return b }), true, ErrCorrupt},
		{"entry type", mod(func(b []byte) []byte { b[bekHeaderLen+2] = 9; return b }), true, ErrCorrupt},
		{"truncated entry", mod(func(b []byte) []byte {
			b = b[:bekHeaderLen+entryHeaderLen+4]
			binary.LittleEndian.PutUint32(b, uint32(len(b)))
			return b
		}), true, ErrCorrupt},
		// the GUID entry's data sits before the 44-byte key entry
		{"other volume", mod(func(b []byte) []byte { b[len(b)-44-16]++; return b }), true, ErrCorrupt},
		{"nested type", mod(func(b []byte) []byte {
			b[bekHeaderLen+entryHeaderLen+startupKeyHeaderLen+2] = 9
			return b
		}), true, ErrCorrupt},
		{"nested value", mod(func(b []byte) []byte {
			b[bekHeaderLen+entryHeaderLen+startupKeyHeaderLen+4] = 0x33
			return b
		}), true, ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok, err := startupKey(c.b, formatGUID(vmk[:]), formatGUID(vol[:]))
			if ok != c.ok || (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
				t.Errorf("ok %v err %v, want ok %v err %v", ok, err, c.ok, c.want)
			}
		})
	}
}

func TestStartupKeyEntries(t *testing.T) {
	vmk, vol := [16]byte{5}, [16]byte{6}
	build := func(nested []byte) []byte {
		e := mkEntry(entryStartupKey, valueExternalKey, append(make([]byte, startupKeyHeaderLen), nested...))
		h := make([]byte, bekHeaderLen)
		binary.LittleEndian.PutUint32(h, uint32(bekHeaderLen+len(e)))
		binary.LittleEndian.PutUint32(h[4:], 1)
		copy(h[16:], vmk[:])
		return append(h, e...)
	}
	for name, nested := range map[string][]byte{
		"no key":      mkEntry(entryProperty, valueString, []byte{'x', 0}),
		"short key":   mkEntry(entryProperty, valueKey, []byte{1}),
		"short GUID":  mkEntry(entryVolumeGUID, valueGUID, []byte{1}),
		"nested size": {9, 0, 0, 0},
	} {
		if _, ok, err := startupKey(build(nested), formatGUID(vmk[:]), formatGUID(vol[:])); !ok || !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
	// a header whose entry header does not fit
	b := build(nil)[:bekHeaderLen+entryHeaderLen]
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	if _, ok, err := startupKey(b, formatGUID(vmk[:]), formatGUID(vol[:])); !ok || !errors.Is(err, ErrCorrupt) {
		t.Errorf("entry header only: %v %v", ok, err)
	}
	// through Open: a BEK file for the protector, malformed, is reported
	s := defaultSpec()
	s.protectors = []protSpec{{prot: StartupKey, guid: vmk, bekKey: bytes.Repeat([]byte{1}, 32)}}
	s.volGUID = vol
	img, _ := buildImage(t, s)
	bad := build(mkEntry(entryProperty, valueString, []byte{'x', 0}))
	if _, err := open(t, img, string(bad), DefaultLimits); !errors.Is(err, ErrCorrupt) {
		t.Errorf("startup key without key: %v", err)
	}
}

func TestRecoveryPassword(t *testing.T) {
	good := testRecovery
	if _, ok := recoveryInitial([]byte(good)); !ok {
		t.Fatal("good recovery password refused")
	}
	for _, bad := range []string{
		"",
		good[:54],
		good + "\r",
		strings.Replace(good, "-", "+", 1),
		strings.Replace(good, "000011", "00001a", 1),
		strings.Replace(good, "000011", "000012", 1),
		strings.Replace(good, "000011", "720896", 1),
		good[:48] + "0000-88",
	} {
		if _, ok := recoveryInitial([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPassword(t *testing.T) {
	if _, ok := passwordInitial([]byte{0xff}); ok {
		t.Error("invalid UTF-8 accepted")
	}
	a, _ := passwordInitial([]byte("ab\x00cd"))
	b, _ := passwordInitial([]byte("ab"))
	if a != b {
		t.Error("the password does not end at NUL as cryptsetup's does")
	}
	s := defaultSpec()
	img, _ := buildImage(t, s)
	if _, err := open(t, img, "\xff", DefaultLimits); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("invalid UTF-8: %v", err)
	}
}

func TestVMKEntries(t *testing.T) {
	guid := make([]byte, vmkHeaderLen)
	for name, nested := range map[string][]byte{
		"short stretch": mkEntry(entryProperty, valueStretchKey, []byte{1}),
		"short ccm":     mkEntry(entryProperty, valueEncryptedKey, []byte{1}),
		"short key":     mkEntry(entryProperty, valueKey, []byte{1}),
	} {
		if _, err := parseVMK(append(append([]byte(nil), guid...), nested...)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseVMK(guid[:4]); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short entry: %v", err)
	}
	// duplicates keep the first
	two := append(append(append([]byte(nil), guid...),
		mkEntry(entryProperty, valueEncryptedKey, make([]byte, 40))...),
		mkEntry(entryProperty, valueEncryptedKey, make([]byte, 50))...)
	two = append(two, mkEntry(entryProperty, valueKey, make([]byte, 8))...)
	two = append(two, mkEntry(entryProperty, valueKey, make([]byte, 12))...)
	p, err := parseVMK(two)
	if err != nil || len(p.encrypted.ct) != 12 || len(p.clearKey) != 4 {
		t.Errorf("duplicates: %v", err)
	}
}

func TestMetadataEntries(t *testing.T) {
	var in Info
	for name, e := range map[string][]byte{
		"short header entry": mkEntry(entryVolumeHeader, 0x0f, []byte{1}),
		"short vmk":          mkEntry(entryVMK, 8, []byte{1}),
		"short fvek":         mkEntry(entryFVEK, valueEncryptedKey, []byte{1}),
	} {
		if err := in.parseEntries(e); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	two := append(mkEntry(entryFVEK, valueEncryptedKey, make([]byte, 40)), mkEntry(entryFVEK, valueEncryptedKey, make([]byte, 50))...)
	two = append(two, mkEntry(entryDescription, valueString, []byte{'a', 0})...)
	two = append(two, mkEntry(entryDescription, valueString, []byte{'b', 0})...)
	in = Info{}
	if err := in.parseEntries(two); err != nil || len(in.fvek.ct) != 12 || in.Description != "a" {
		t.Errorf("duplicates: %v %q", err, in.Description)
	}
}

func TestUnlockEdges(t *testing.T) {
	in := &Info{Protectors: []Protector{
		{Protection: ClearKey},
		{Protection: Password},
		{Protection: StartupKey},
		{Protection: SmartCard},
	}}
	if _, err := unlock(in, []byte("x"), DefaultLimits); !errors.Is(err, ErrWrongSecret) ||
		!strings.Contains(err.Error(), "clear key, password, startup key, smart card") {
		t.Errorf("%v", err)
	}
	if _, err := unlock(&Info{}, nil, DefaultLimits); !strings.Contains(err.Error(), "none") {
		t.Errorf("%v", err)
	}
}

func TestKeyOpening(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	d, _ := parseCCM(seal(t, key, []byte{1, 2, 3}, 1))
	if _, ok, err := openKey(key, d); !ok || !errors.Is(err, ErrCorrupt) {
		t.Errorf("record shorter than its header: %v %v", ok, err)
	}
	if _, ok := ccmOpen(key[:5], d); ok {
		t.Error("a 5-byte AES key opened")
	}
	// a validation record the VMK opens but that holds another hash type
	in := &Info{}
	rec := make([]byte, 44)
	binary.LittleEndian.PutUint16(rec[4:], 1)
	binary.LittleEndian.PutUint16(rec[8:], 0x1111)
	v, _ := parseCCM(seal(t, key, rec, 2))
	in.validation = *v
	if err := in.checkDigest(key); !errors.Is(err, ErrUnsupported) {
		t.Errorf("hash type: %v", err)
	}
	short, _ := parseCCM(seal(t, key, rec[:10], 2))
	in.validation = *short
	if err := in.checkDigest(key); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short validation: %v", err)
	}
	// a VMK that does not open the volume key
	in.fvek, _ = parseCCM(seal(t, bytes.Repeat([]byte{8}, 32), keyRecord(make([]byte, 32), 0), 3))
	if _, err := in.fvekFrom(key); !errors.Is(err, ErrCorrupt) {
		t.Errorf("foreign volume key: %v", err)
	}
	in.fvek, _ = parseCCM(seal(t, key, []byte{1, 2}, 3))
	if _, err := in.fvekFrom(key); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short volume key record: %v", err)
	}
}

func TestSectorCipherErrors(t *testing.T) {
	for _, m := range []Method{AES128CBC, AES128CBCElephant, AES128XTS} {
		if _, err := newSectorCipher(m, make([]byte, 5), 512); err == nil {
			t.Errorf("%v with a 5-byte key", m)
		}
	}
	if _, err := newSectorCipher(0x9999, make([]byte, 32), 512); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown method: %v", err)
	}
	if sectorShift(4096) != 12 || sectorShift(512) != 9 {
		t.Error("sector shift")
	}
}

func TestStrings(t *testing.T) {
	for k, want := range map[Kind]string{Normal: "normal", EncryptOnWrite: "encrypt-on-write", UnknownKind: "unknown"} {
		if k.String() != want {
			t.Errorf("%d: %s", k, k)
		}
	}
	for p, want := range map[Protection]string{ClearKey: "clear key", TPM: "TPM", StartupKey: "startup key",
		TPMAndPIN: "TPM and PIN", RecoveryPassword: "recovery password", SmartCard: "smart card",
		Password: "password", 0x4444: "unknown"} {
		if p.String() != want {
			t.Errorf("%#x: %s", uint16(p), p)
		}
	}
	for m, want := range map[Method][2]any{
		AES128CBCElephant: {"aes-cbc-elephant", 256}, AES256CBCElephant: {"aes-cbc-elephant", 512},
		AES128CBC: {"aes-cbc-eboiv", 128}, AES256CBC: {"aes-cbc-eboiv", 256},
		AES128XTS: {"aes-xts-plain64", 256}, AES256XTS: {"aes-xts-plain64", 512}, 0x1: {"unknown", 0},
	} {
		if m.String() != want[0] || m.KeyBits() != want[1] {
			t.Errorf("%#x: %s %d", uint16(m), m, m.KeyBits())
		}
	}
	if s := (region{start: 0, end: 1, zero: true}).String(); s != "[0,1) zero" {
		t.Error(s)
	}
	if s := (region{start: 0, end: 1, src: 5}).String(); s != "[0,1) from 5" {
		t.Error(s)
	}
	if decodeUTF16([]byte{'a', 0, 0, 0, 'b', 0}) != "a" {
		t.Error("UTF-16 does not stop at NUL")
	}
}

func TestFileSizeFails(t *testing.T) {
	img, _ := buildImage(t, defaultSpec())
	path := filepath.Join(t.TempDir(), "v.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := fileSize
	defer func() { fileSize = saved }()
	fileSize = func(*os.File) (int64, error) { return 0, errors.New("no size") }
	if _, err := Open(path, []byte("secret")); err == nil || !strings.Contains(err.Error(), "no size") {
		t.Errorf("%v", err)
	}
	fileSize = saved
	f, _ := os.Open(path)
	f.Close()
	if _, err := fileSize(f); err == nil {
		t.Error("Stat of a closed file")
	}
}

func TestShortDevice(t *testing.T) {
	img, _ := buildImage(t, defaultSpec())
	if _, err := parseVolumeHeader(img[:100]); !errors.Is(err, ErrNotBitLocker) {
		t.Errorf("short header: %v", err)
	}
	// The device claims its full size but ends inside the metadata: once
	// inside the block header, once inside the block.
	offs := defaultSpec().metaOffs
	for _, n := range []int{(320 << 10) + 10, (320 << 10) + 100} {
		cut := append([]byte(nil), img[:n]...)
		for _, o := range offs[:2] {
			cut[o+200]++ // the first two copies fail their CRC
		}
		if _, err := ReadInfo(bytes.NewReader(cut), int64(len(img))); !errors.Is(err, ErrCorrupt) {
			t.Errorf("cut at %d: %v", n, err)
		}
	}
}

func TestSectorSizeZero(t *testing.T) {
	img, plain := buildImage(t, defaultSpec())
	img[11], img[12] = 0, 0 // means 512
	d, err := open(t, img, "secret", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadAll(t, d), plain) {
		t.Error("differs")
	}
}

func TestEntryListEnd(t *testing.T) {
	var in Info
	b := append(mkEntry(entryDescription, valueString, []byte{'a', 0}), 0, 0, 0, 0, 0xff, 0xff)
	if err := in.parseEntries(b); err != nil || in.Description != "a" {
		t.Errorf("%v %q", err, in.Description)
	}
}

func TestBEKSecondKey(t *testing.T) {
	vmk, vol := [16]byte{5}, [16]byte{6}
	b := bekFile([]byte{1, 2}, vmk, vol, false)
	e := mkEntry(entryProperty, valueKey, []byte{0, 0, 0, 0, 9})
	b = append(b, e...)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	// the outer entry's size still covers only the first key: grow it
	off := bekHeaderLen
	binary.LittleEndian.PutUint16(b[off:], binary.LittleEndian.Uint16(b[off:])+uint16(len(e)))
	k, ok, err := startupKey(b, formatGUID(vmk[:]), formatGUID(vol[:]))
	if err != nil || !ok || !bytes.Equal(k, []byte{1, 2}) {
		t.Errorf("%x %v %v", k, ok, err)
	}
}

func TestVMKRecordSize(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	rec := keyRecord(testVMK, 0x2000)
	rec[0]++ // records one byte more than its ciphertext
	d, _ := parseCCM(seal(t, key, rec, 1))
	in := &Info{Protectors: []Protector{{Protection: ClearKey, clearKey: key, encrypted: d}}}
	if _, err := unlock(in, nil, DefaultLimits); !errors.Is(err, ErrCorrupt) {
		t.Errorf("%v", err)
	}
}

func TestNegativeSize(t *testing.T) {
	if _, err := OpenFrom(memDev{bytes.NewReader(nil)}, -1, nil, DefaultLimits); err == nil {
		t.Error("negative size")
	}
}

// TestDiffuserRoundTrip checks the decrypt diffusers against encrypt ports
// of the same dm-crypt functions: the corpus proves decrypt matches Windows,
// this that every index of a 4 KiB sector is reached.
func TestDiffuserRoundTrip(t *testing.T) {
	for _, n := range []int{128, 1024} {
		d := make([]uint32, n)
		for i := range d {
			d[i] = uint32(i*2654435761 + 1)
		}
		orig := append([]uint32(nil), d...)
		diffuserAEncrypt(d)
		diffuserBEncrypt(d)
		diffuserBDecrypt(d)
		diffuserADecrypt(d)
		for i := range d {
			if d[i] != orig[i] {
				t.Fatalf("n=%d differs at %d", n, i)
			}
		}
	}
}

func diffuserAEncrypt(d []uint32) {
	n := len(d)
	for range 5 {
		i1, i2, i3 := n-1, n-2-1, n-5-1
		for i1 > 0 {
			d[i1] -= d[i2] ^ d[i3]
			i1, i2, i3 = i1-1, i2-1, i3-1
			d[i1] -= d[i2] ^ rotl(d[i3], 13)
			i1, i2, i3 = i1-1, i2-1, i3-1
			if i2 < 0 {
				i2 += n
			}
			d[i1] -= d[i2] ^ d[i3]
			i1, i2, i3 = i1-1, i2-1, i3-1
			if i3 < 0 {
				i3 += n
			}
			d[i1] -= d[i2] ^ rotl(d[i3], 9)
			i1, i2, i3 = i1-1, i2-1, i3-1
		}
	}
}

func diffuserBEncrypt(d []uint32) {
	n := len(d)
	for range 3 {
		i1, i2, i3 := n-1, 2-1, 5-1
		for i1 > 0 {
			d[i1] -= d[i2] ^ rotl(d[i3], 25)
			i1, i2, i3 = i1-1, i2-1, i3-1
			if i3 < 0 {
				i3 += n
			}
			d[i1] -= d[i2] ^ d[i3]
			i1, i2, i3 = i1-1, i2-1, i3-1
			if i2 < 0 {
				i2 += n
			}
			d[i1] -= d[i2] ^ rotl(d[i3], 10)
			i1, i2, i3 = i1-1, i2-1, i3-1
			d[i1] -= d[i2] ^ d[i3]
			i1, i2, i3 = i1-1, i2-1, i3-1
		}
	}
}
