package bitlocker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-compressions/xz"
)

// The interoperability corpus is cryptsetup's tests/bitlk-images.tar.xz:
// BitLocker volumes made by Windows, with their passwords, recovery
// passwords and the SHA-256 of what cryptsetup's bitlkOpen maps in
// images.conf (tests/bitlk-compat-test). It is GPL-2.0+, so it is never
// committed here: the test reads the archive named by BITLK_IMAGES (CI
// downloads it) and skips, loudly, without it.
const corpusEnv = "BITLK_IMAGES"

// corpusMaxEntry bounds what one archive member may expand to; the largest
// image is 128 MiB.
const corpusMaxEntry = 256 << 20

// eachCorpusMember calls f for every regular member of the archive and,
// when images is set, every sparse one (the images), one at a time so that
// only one image is in memory.
func eachCorpusMember(t *testing.T, f func(name string, b []byte), images bool) {
	t.Helper()
	path := os.Getenv(corpusEnv)
	if path == "" {
		t.Skipf("%s is not set: the Windows-made images are not available, interoperability is NOT tested", corpusEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	xr, err := xz.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("corpus: xz: %v", err)
	}
	tr := tar.NewReader(xr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("corpus: tar: %v", err)
		}
		if h.Typeflag != tar.TypeReg && (!images || h.Typeflag != tar.TypeGNUSparse) {
			continue
		}
		if h.Size > corpusMaxEntry {
			t.Fatalf("corpus: %s declares %d bytes, over %d", h.Name, h.Size, corpusMaxEntry)
		}
		b, err := io.ReadAll(io.LimitReader(tr, corpusMaxEntry+1))
		if err != nil {
			t.Fatalf("corpus: %s: %v", h.Name, err)
		}
		f(h.Name[strings.LastIndex(h.Name, "/")+1:], b)
	}
}

// parseImagesConf reads images.conf: [section] then KEY=VALUE lines.
func parseImagesConf(b []byte) map[string]map[string]string {
	conf := map[string]map[string]string{}
	var cur map[string]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			cur = map[string]string{}
			conf[line[1:len(line)-1]] = cur
		case cur != nil && strings.Contains(line, "="):
			k, v, _ := strings.Cut(line, "=")
			cur[k] = v
		}
	}
	return conf
}

type memDev struct{ *bytes.Reader }

func (memDev) Close() error { return nil }

// The images cryptsetup itself does not activate (bitlk-compat-test answers
// N/A): they must be refused as unsupported, never read wrong.
var corpusUnsupported = map[string]bool{
	"bitlk-partially-encrypted-aes-cbc-128": true,
	"bitlk-aes-xts-128-eow":                 true,
}

func TestCorpus(t *testing.T) {
	// The archive holds images before images.conf and the .BEK files, so a
	// first pass reads only those and a second one the images.
	var conf map[string]map[string]string
	beks := map[string][]byte{}
	eachCorpusMember(t, func(name string, b []byte) {
		switch {
		case name == "images.conf":
			conf = parseImagesConf(b)
		case strings.HasSuffix(name, ".BEK"):
			beks[strings.ToLower(strings.TrimSuffix(name, ".BEK"))] = b
		}
	}, false)
	if conf == nil {
		t.Fatal("no images.conf in the corpus")
	}
	images := 0
	eachCorpusMember(t, func(name string, b []byte) {
		if !strings.HasSuffix(name, ".img") {
			return
		}
		img := strings.TrimSuffix(name, ".img")
		c, ok := conf[img]
		if !ok {
			t.Errorf("%s: no section in images.conf", img)
			return
		}
		images++
		t.Run(img, func(t *testing.T) { checkCorpusImage(t, img, c, b, beks) })
	}, true)
	if images == 0 {
		t.Fatal("no image in the corpus")
	}
	t.Logf("%d Windows-made images checked", images)
}

func checkCorpusImage(t *testing.T, img string, c map[string]string, b []byte, beks map[string][]byte) {
	dev := memDev{bytes.NewReader(b)}
	size := int64(len(b))
	in, err := ReadInfo(dev, size)
	if err != nil {
		t.Fatalf("ReadInfo: %v", err)
	}
	if in.GUID != c["GUID"] {
		t.Errorf("GUID %s, images.conf %s", in.GUID, c["GUID"])
	}
	if in.Method.String() != c["CIPHER"] {
		t.Errorf("cipher %s, images.conf %s", in.Method, c["CIPHER"])
	}
	switch in.VolumeSize {
	case 104857600, 134217728, 105906176:
	default:
		t.Errorf("volume size %d (bitlk-compat-test accepts three)", in.VolumeSize)
	}
	byProt := map[Protection][]string{}
	for _, p := range in.Protectors {
		byProt[p.Protection] = append(byProt[p.Protection], p.GUID)
	}
	for key, prot := range map[string]Protection{
		"PW_VMK_GUID": Password, "RP_VMK_GUID": RecoveryPassword, "SC_VMK_GUID": SmartCard,
		"SK_VMK_GUID": StartupKey, "CLEARKEY_VMK_GUID": ClearKey, "RP2_VMK_GUID": RecoveryPassword,
	} {
		if want := c[key]; want != "" && !contains(byProt[prot], want) {
			t.Errorf("%s %s is not among the %s protectors %v", key, want, prot, byProt[prot])
		}
	}

	type attempt struct{ label, secret string }
	var attempts []attempt
	for _, k := range []string{"PW", "RP", "RP2"} {
		if c[k] != "" {
			attempts = append(attempts, attempt{k, c[k]})
		}
	}
	if g := c["SK_VMK_GUID"]; g != "" {
		bek, ok := beks[g]
		if !ok {
			t.Fatalf("no .BEK file for %s", g)
		}
		attempts = append(attempts, attempt{"BEK", string(bek)})
	}
	if c["CLEARKEY_VMK_GUID"] != "" {
		attempts = append(attempts, attempt{"clear key, nil secret", ""})
	}
	if len(attempts) == 0 {
		t.Fatal("no secret to try")
	}

	var key []byte
	for _, a := range attempts {
		var secret []byte
		if a.secret != "" {
			secret = []byte(a.secret)
		}
		d, err := OpenFrom(dev, size, secret, DefaultLimits)
		if corpusUnsupported[img] {
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("%s: %v, want ErrUnsupported as cryptsetup refuses it", a.label, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", a.label, err)
			continue
		}
		if key == nil {
			key = d.key
			checkCorpusContent(t, d, c)
		} else if !bytes.Equal(key, d.key) {
			t.Errorf("%s opened another volume key than %s", a.label, attempts[0].label)
		}
	}
	if corpusUnsupported[img] {
		return
	}
	// A wrong password must not open it, unless a clear-key protector
	// opens it with anything (cryptsetup BITLK_get_volume_key).
	_, err = OpenFrom(dev, size, []byte("not the password"), DefaultLimits)
	if len(byProt[ClearKey]) > 0 {
		if err != nil {
			t.Errorf("clear key with an unrelated secret: %v", err)
		}
	} else if !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong password: %v, want ErrWrongSecret", err)
	}
}

// checkCorpusContent compares the whole decrypted device with cryptsetup's
// SHA-256 and the file system UUID blkid reports.
func checkCorpusContent(t *testing.T, d *Device, c map[string]string) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(d, 0, d.Size())); err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := c["SHA256SUM"]; want != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			t.Errorf("SHA-256 %s, cryptsetup %s", got, want)
		}
	}
	boot := make([]byte, 512)
	if _, err := d.ReadAt(boot, 0); err != nil {
		t.Fatalf("boot sector: %v", err)
	}
	if want := c["UUID"]; want != "" {
		if got := fsUUID(boot); got != want {
			t.Logf("boot sector:\n%s", hex.Dump(boot[:128]))
			t.Errorf("file system UUID %s, blkid %s", got, want)
		}
	}
}

// fsUUID is what blkid prints for the boot sector: the NTFS serial number
// (offset 72, 8 bytes, upper-case hex of the little-endian value), the exFAT
// volume serial (offset 100) or the FAT volume ID (offset 67 for FAT32, 39
// for FAT12/16), XXXX-XXXX.
func fsUUID(b []byte) string {
	switch string(b[3:11]) {
	case "NTFS    ":
		var s [8]byte
		for i := range s {
			s[i] = b[72+7-i]
		}
		return strings.ToUpper(hex.EncodeToString(s[:]))
	case "EXFAT   ":
		return serial32(b[100:104])
	}
	if string(b[82:90]) == "FAT32   " {
		return serial32(b[67:71])
	}
	return serial32(b[39:43]) // FAT12/16
}

func serial32(b []byte) string {
	id := strings.ToUpper(hex.EncodeToString([]byte{b[3], b[2], b[1], b[0]}))
	return id[:4] + "-" + id[4:]
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
