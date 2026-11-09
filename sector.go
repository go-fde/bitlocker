package bitlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/go-encryptions/xts"
)

// sectorCipher decrypts one sector in place. pos is the sector's byte
// offset on the device, which every method mixes in: the CBC IV is
// AES(LE128(pos)), the XTS tweak is pos / sector size, the Elephant sector
// key is AES over pos (Linux dm-crypt eboiv, elephant, plain64 with
// iv_large_sectors, as cryptsetup sets them up for BitLocker).
//
// s holds the buffers a sector needs. Anything handed to a cipher.Block
// escapes to the heap, so a local array would cost an allocation per
// sector; one scratch per ReadAt keeps a Device safe for concurrent use
// without a lock.
type sectorCipher interface {
	decrypt(p []byte, pos uint64, s *scratch)
}

type scratch struct {
	iv, es [16]byte
	ks     [32]byte
	words  []uint32 // sector size / 4, for the Elephant diffuser
}

func newScratch(sectorSize int) *scratch {
	return &scratch{words: make([]uint32, sectorSize/4)}
}

func newSectorCipher(m Method, key []byte, sectorSize int) (sectorCipher, error) {
	switch m {
	case AES128CBC, AES256CBC:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return &cbcCipher{b: b}, nil
	case AES128CBCElephant, AES256CBCElephant:
		// The data key and the Elephant key have the same length.
		half := len(key) / 2
		b, err := aes.NewCipher(key[:half])
		if err != nil {
			return nil, err
		}
		e, _ := aes.NewCipher(key[half:])
		return &elephantCipher{cbcCipher{b: b}, e}, nil
	case AES128XTS, AES256XTS:
		c, err := xts.NewCipher(aes.NewCipher, key)
		if err != nil {
			return nil, err
		}
		return &xtsCipher{c: c, shift: uint(sectorShift(sectorSize))}, nil
	}
	return nil, unsupported("encryption method %#04x", uint16(m))
}

func sectorShift(n int) int {
	if n == 4096 {
		return 12
	}
	return 9
}

// cbcCipher is AES-CBC with dm-crypt's "eboiv": IV = AES_K(LE128(pos)).
type cbcCipher struct{ b cipher.Block }

// decrypt is CBC from the last block back to the first, so that each block
// is decrypted in place while the ciphertext block before it is still
// there to XOR: no buffer and no cipher.BlockMode per sector.
func (c *cbcCipher) decrypt(p []byte, pos uint64, s *scratch) {
	s.iv = [16]byte{}
	binary.LittleEndian.PutUint64(s.iv[:], pos)
	c.b.Encrypt(s.iv[:], s.iv[:])
	for i := len(p) - 16; i >= 0; i -= 16 {
		blk := p[i : i+16]
		c.b.Decrypt(blk, blk)
		prev := s.iv[:]
		if i > 0 {
			prev = p[i-16 : i]
		}
		subtle.XORBytes(blk, blk, prev)
	}
}

// elephantCipher is AES-CBC (eboiv) followed by the Elephant diffuser
// (Linux dm-crypt crypt_iv_elephant, read direction).
type elephantCipher struct {
	cbcCipher
	e cipher.Block
}

func (c *elephantCipher) decrypt(p []byte, pos uint64, s *scratch) {
	c.cbcCipher.decrypt(p, pos, s)
	s.es = [16]byte{}
	binary.LittleEndian.PutUint64(s.es[:], pos)
	c.e.Encrypt(s.ks[:16], s.es[:])
	s.es[15] = 0x80
	c.e.Encrypt(s.ks[16:], s.es[:])

	d := s.words[:len(p)/4]
	for i := range d {
		d[i] = binary.LittleEndian.Uint32(p[4*i:])
	}
	diffuserBDecrypt(d)
	diffuserADecrypt(d)
	for i := range d {
		binary.LittleEndian.PutUint32(p[4*i:], d[i])
	}
	for i := 0; i < len(p); i += 32 {
		subtle.XORBytes(p[i:i+32], p[i:i+32], s.ks[:])
	}
}

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

// diffuserADecrypt is dm-crypt's diffuser_a_decrypt, index for index: five
// cycles, rotations {9, 0, 13, 0}, sources n-2 and n-5 wrapping at the
// points the kernel checks them.
func diffuserADecrypt(d []uint32) {
	n := len(d)
	for range 5 {
		i1, i2, i3 := 0, n-2, n-5
		for i1 < n-1 {
			d[i1] += d[i2] ^ rotl(d[i3], 9)
			i1, i2, i3 = i1+1, i2+1, i3+1
			if i3 >= n {
				i3 -= n
			}
			d[i1] += d[i2] ^ d[i3]
			i1, i2, i3 = i1+1, i2+1, i3+1
			if i2 >= n {
				i2 -= n
			}
			d[i1] += d[i2] ^ rotl(d[i3], 13)
			i1, i2, i3 = i1+1, i2+1, i3+1
			d[i1] += d[i2] ^ d[i3]
			i1, i2, i3 = i1+1, i2+1, i3+1
		}
	}
}

// diffuserBDecrypt is dm-crypt's diffuser_b_decrypt: three cycles,
// rotations {0, 10, 0, 25}, sources 2 and 5 ahead.
func diffuserBDecrypt(d []uint32) {
	n := len(d)
	for range 3 {
		i1, i2, i3 := 0, 2, 5
		for i1 < n-1 {
			d[i1] += d[i2] ^ d[i3]
			i1, i2, i3 = i1+1, i2+1, i3+1
			d[i1] += d[i2] ^ rotl(d[i3], 10)
			i1, i2, i3 = i1+1, i2+1, i3+1
			if i2 >= n {
				i2 -= n
			}
			d[i1] += d[i2] ^ d[i3]
			i1, i2, i3 = i1+1, i2+1, i3+1
			if i3 >= n {
				i3 -= n
			}
			d[i1] += d[i2] ^ rotl(d[i3], 25)
			i1, i2, i3 = i1+1, i2+1, i3+1
		}
	}
}

// xtsCipher is AES-XTS with the tweak pos / sector size (dm-crypt plain64,
// iv_large_sectors for 4 KiB sectors).
type xtsCipher struct {
	c     *xts.Cipher
	shift uint
}

func (c *xtsCipher) decrypt(p []byte, pos uint64, _ *scratch) {
	c.c.Decrypt(p, p, pos>>c.shift)
}

// region is a range of the decrypted device that does not map to the same
// offset of the encrypted one.
type region struct {
	start, end uint64 // logical [start, end)
	zero       bool   // reads as zeros
	src        uint64 // otherwise read from here, encrypted at here
}

// layout is the mapping cryptsetup's _activate builds with device-mapper:
// the first HeaderSize bytes come from HeaderOffset, the three metadata
// areas and the header's own location read as zeros, and every other sector
// is decrypted where it lies.
type layout struct {
	size    uint64
	regions []region
}

func newLayout(in *Info, size uint64) (layout, error) {
	ss := uint64(in.SectorSize)
	l := layout{size: size}
	l.regions = append(l.regions, region{start: 0, end: in.HeaderSize, src: in.HeaderOffset})
	for _, off := range in.MetadataOffsets {
		l.regions = append(l.regions, region{start: off, end: off + metadataAreaSize, zero: true})
	}
	l.regions = append(l.regions, region{start: in.HeaderOffset, end: in.HeaderOffset + in.HeaderSize, zero: true})
	for i, r := range l.regions {
		if r.end < r.start || r.end > size || r.start%ss != 0 || r.end%ss != 0 || r.src%ss != 0 ||
			(!r.zero && (r.src > size || size-r.src < r.end-r.start)) {
			return l, corrupt("region %d [%d, %d) from %d outside a device of %d bytes or off its %d-byte sectors",
				i, r.start, r.end, r.src, size, ss)
		}
		for _, q := range l.regions[:i] {
			if r.start < q.end && q.start < r.end {
				return l, corrupt("regions [%d, %d) and [%d, %d) overlap", q.start, q.end, r.start, r.end)
			}
		}
	}
	return l, nil
}

// locate returns the region holding logical sector start pos, or nil for an
// identity sector.
func (l *layout) locate(pos uint64) *region {
	for i := range l.regions {
		if r := &l.regions[i]; pos >= r.start && pos < r.end {
			return r
		}
	}
	return nil
}

// String is for error messages and tests.
func (r region) String() string {
	if r.zero {
		return fmt.Sprintf("[%d,%d) zero", r.start, r.end)
	}
	return fmt.Sprintf("[%d,%d) from %d", r.start, r.end, r.src)
}
