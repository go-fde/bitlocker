package bitlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/go-encryptions/ccm"
	"github.com/go-encryptions/xts"
)

// A test-only writer of BitLocker volumes, so that every refusal can be
// reached without the GPL corpus. It writes what cryptsetup reads; the
// corpus test is what proves that this is also what Windows writes.

type protSpec struct {
	prot     Protection
	guid     [16]byte
	password string // Password or RecoveryPassword
	bekKey   []byte // StartupKey
	clearKey []byte // ClearKey
}

type imageSpec struct {
	size       int
	sectorSize int
	method     Method
	togo       bool
	kindGUID   [16]byte
	state      uint16
	protectors []protSpec
	volGUID    [16]byte
	fvekLen    int // key material length; 0 = what the method needs
	hdrOff     uint64
	hdrSize    uint64
	metaOffs   [3]uint64
	// mutate edits the metadata block before the CRC and the digest are
	// computed; mutateSealed after (only the CRC is recomputed).
	mutate       func(block []byte) []byte
	mutateSealed func(block []byte)
	noFVEK       bool
	noHeader     bool
	vmkLen       int
}

func defaultSpec() imageSpec {
	return imageSpec{
		size:       1 << 20,
		sectorSize: 512,
		method:     AES128XTS,
		kindGUID:   guidNormal,
		state:      stateNormal,
		volGUID:    [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01},
		protectors: []protSpec{{prot: Password, guid: [16]byte{1}, password: "secret"}},
		hdrOff:     448 << 10,
		hdrSize:    8 << 10,
		metaOffs:   [3]uint64{64 << 10, 192 << 10, 320 << 10},
	}
}

var testVMK = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0xa0 + i)
	}
	return b
}()

func fvekFor(m Method, n int) []byte {
	if n == 0 {
		n = map[Method]int{AES128CBCElephant: 64, AES256CBCElephant: 64, AES128CBC: 16,
			AES256CBC: 32, AES128XTS: 32, AES256XTS: 64}[m]
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func seal(t testing.TB, key, plaintext []byte, nonce byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ccm.NewCCM(b, tagLen, nonceLen)
	n := make([]byte, nonceLen)
	n[0] = nonce
	out := a.Seal(nil, n, plaintext, nil)
	ct, tag := out[:len(plaintext)], out[len(plaintext):]
	// on disk: nonce, tag, ciphertext
	return append(append(append([]byte(nil), n...), tag...), ct...)
}

// keyRecord is the plaintext of an encrypted key: size, version, method,
// then the key. size counts the record, which is the ciphertext length.
func keyRecord(key []byte, method uint32) []byte {
	r := make([]byte, keyMetadataLen+len(key))
	binary.LittleEndian.PutUint16(r, uint16(len(r)))
	binary.LittleEndian.PutUint16(r[2:], 1)
	binary.LittleEndian.PutUint32(r[8:], method)
	copy(r[keyMetadataLen:], key)
	return r
}

func mkEntry(typ, value uint16, data []byte) []byte {
	e := make([]byte, entryHeaderLen, entryHeaderLen+len(data))
	binary.LittleEndian.PutUint16(e, uint16(entryHeaderLen+len(data)))
	binary.LittleEndian.PutUint16(e[2:], typ)
	binary.LittleEndian.PutUint16(e[4:], value)
	binary.LittleEndian.PutUint16(e[6:], 1)
	return append(e, data...)
}

func vmkEntry(t testing.TB, p protSpec, vmk []byte, nonce byte) []byte {
	head := make([]byte, vmkHeaderLen)
	copy(head, p.guid[:])
	binary.LittleEndian.PutUint16(head[26:], uint16(p.prot))
	salt := [16]byte{nonce, 0x5a}
	var key []byte
	var nested []byte
	switch p.prot {
	case Password, RecoveryPassword:
		var init [32]byte
		var ok bool
		if p.prot == Password {
			init, ok = passwordInitial([]byte(p.password))
		} else {
			init, ok = recoveryInitial([]byte(p.password))
		}
		if !ok {
			t.Fatalf("bad test secret %q", p.password)
		}
		k := stretch(init, salt)
		key = k[:]
		sk := make([]byte, 4+16)
		binary.LittleEndian.PutUint32(sk, 0x1000)
		copy(sk[4:], salt[:])
		nested = append(nested, mkEntry(entryProperty, valueStretchKey, sk)...)
	case StartupKey:
		key = p.bekKey
	case ClearKey:
		key = p.clearKey
		ck := append(make([]byte, 4), key...)
		nested = append(nested, mkEntry(entryProperty, valueKey, ck)...)
	default:
		key = make([]byte, 32)
	}
	nested = append(nested, mkEntry(entryProperty, valueString, []byte{'n', 0})...)
	nested = append(nested, mkEntry(entryProperty, valueEncryptedKey, seal(t, key, keyRecord(vmk, 0x2000), nonce))...)
	return mkEntry(entryVMK, 8, append(head, nested...))
}

// buildImage returns an encrypted image and the plaintext device cryptsetup
// would map from it.
func buildImage(t testing.TB, s imageSpec) (img, plain []byte) {
	t.Helper()
	ss := s.sectorSize
	img = make([]byte, s.size)
	plain = make([]byte, s.size)
	for i := range plain {
		plain[i] = byte(i*31 + i/ss)
	}
	vmk := testVMK
	if s.vmkLen != 0 {
		vmk = make([]byte, s.vmkLen)
	}
	fvek := fvekFor(s.method, s.fvekLen)

	// metadata block: block header, metadata header, entries
	var entries []byte
	for i, p := range s.protectors {
		entries = append(entries, vmkEntry(t, p, vmk, byte(i+1))...)
	}
	if !s.noFVEK {
		entries = append(entries, mkEntry(entryFVEK, valueEncryptedKey, seal(t, vmk, keyRecord(fvek, uint32(s.method)), 0x40))...)
	}
	if !s.noHeader {
		hd := make([]byte, 16)
		binary.LittleEndian.PutUint64(hd, s.hdrOff)
		binary.LittleEndian.PutUint64(hd[8:], s.hdrSize)
		entries = append(entries, mkEntry(entryVolumeHeader, 0x000f, hd)...)
	}
	entries = append(entries, mkEntry(entryDescription, valueString, []byte{'D', 0, 'E', 0, 'S', 0, 'K', 0})...)

	mh := make([]byte, metadataHeaderLen)
	binary.LittleEndian.PutUint32(mh, uint32(metadataHeaderLen+len(entries)))
	binary.LittleEndian.PutUint32(mh[4:], 1)
	binary.LittleEndian.PutUint32(mh[8:], metadataHeaderLen)
	binary.LittleEndian.PutUint32(mh[12:], uint32(metadataHeaderLen+len(entries)))
	copy(mh[16:], s.volGUID[:])
	binary.LittleEndian.PutUint16(mh[36:], uint16(s.method))

	bh := make([]byte, blockHeaderLen)
	copy(bh, signature)
	binary.LittleEndian.PutUint16(bh[10:], metadataVersion2)
	binary.LittleEndian.PutUint16(bh[12:], s.state)
	binary.LittleEndian.PutUint16(bh[14:], s.state)
	binary.LittleEndian.PutUint64(bh[16:], uint64(s.size))
	binary.LittleEndian.PutUint32(bh[28:], uint32(s.hdrSize/uint64(ss)))
	for i, o := range s.metaOffs {
		binary.LittleEndian.PutUint64(bh[32+8*i:], o)
	}
	binary.LittleEndian.PutUint64(bh[56:], s.hdrOff)

	block := append(append(bh, mh...), entries...)
	for len(block)%16 != 0 {
		block = append(block, 0)
	}
	if s.mutate != nil {
		block = s.mutate(block)
	}
	binary.LittleEndian.PutUint16(block[8:], uint16(len(block)>>4))

	digest := sha256.Sum256(block)
	hr := make([]byte, 44)
	binary.LittleEndian.PutUint16(hr, 44)
	binary.LittleEndian.PutUint16(hr[4:], 1)
	binary.LittleEndian.PutUint16(hr[8:], 0x2005)
	copy(hr[12:], digest[:])
	if s.mutateSealed != nil {
		s.mutateSealed(block)
	}
	val := make([]byte, validationLen)
	binary.LittleEndian.PutUint16(val, validationLen)
	binary.LittleEndian.PutUint16(val[2:], 2)
	binary.LittleEndian.PutUint32(val[4:], crc32.ChecksumIEEE(block))
	binary.LittleEndian.PutUint16(val[8:], entryHeaderLen+validationDataLen)
	binary.LittleEndian.PutUint16(val[12:], valueEncryptedKey)
	copy(val[16:], seal(t, vmk, hr, 0x77))

	// regions: the header copy, zeros, identity
	key := fvek
	if s.method == AES128CBCElephant {
		key = append(append([]byte(nil), fvek[:16]...), fvek[32:48]...)
	}
	enc := newTestEncrypter(s.method, key, ss)
	for pos := 0; pos < s.size; pos += ss {
		p := uint64(pos)
		inZero := p >= s.hdrOff && p < s.hdrOff+s.hdrSize
		for _, o := range s.metaOffs {
			if p >= o && p < o+metadataAreaSize {
				inZero = true
			}
		}
		if inZero {
			clear(plain[pos : pos+ss])
			continue
		}
		copy(img[pos:pos+ss], plain[pos:pos+ss])
		enc(img[pos:pos+ss], p)
	}
	// the original first sectors live, encrypted, at hdrOff
	for i := uint64(0); i < s.hdrSize && s.hdrOff+i+uint64(ss) <= uint64(s.size); i += uint64(ss) {
		copy(img[s.hdrOff+i:], plain[i:i+uint64(ss)])
		enc(img[s.hdrOff+i:s.hdrOff+i+uint64(ss)], s.hdrOff+i)
	}
	for _, o := range s.metaOffs {
		if o+metadataAreaSize <= uint64(s.size) {
			clear(img[o : o+metadataAreaSize])
			copy(img[o:], block)
			copy(img[o+uint64(len(block)):], val)
		}
	}
	// sector 0 last: the volume header
	clear(img[:512])
	sig := signature
	sb := superblockOff
	if s.togo {
		sig, sb = signatureToGo, superblockOffToGo
	}
	copy(img, bootCodeV2)
	copy(img[signatureOff:], sig)
	binary.LittleEndian.PutUint16(img[sectorSizeOff:], uint16(ss))
	copy(img[sb:], s.kindGUID[:])
	for i, o := range s.metaOffs {
		binary.LittleEndian.PutUint64(img[sb+16+8*i:], o)
	}
	return img, plain
}

// newTestEncrypter encrypts sectors the way the method does. A key the
// method cannot use (a spec testing that refusal) leaves the data plain.
func newTestEncrypter(m Method, key []byte, ss int) func(p []byte, pos uint64) {
	noop := func([]byte, uint64) {}
	switch m {
	case AES128XTS, AES256XTS:
		c, err := xts.NewCipher(aes.NewCipher, key)
		if err != nil {
			return noop
		}
		return func(p []byte, pos uint64) { c.Encrypt(p, p, pos/uint64(ss)) }
	case AES128CBC, AES256CBC:
		b, err := aes.NewCipher(key)
		if err != nil {
			return noop
		}
		return func(p []byte, pos uint64) {
			var iv [16]byte
			binary.LittleEndian.PutUint64(iv[:], pos)
			b.Encrypt(iv[:], iv[:])
			cipher.NewCBCEncrypter(b, iv[:]).CryptBlocks(p, p)
		}
	}
	// Elephant encryption is not written here; the corpus covers it.
	return noop
}
