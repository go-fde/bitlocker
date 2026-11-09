package bitlocker

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

// Entry types and value types of the FVE metadata (cryptsetup bitlk.h).
const (
	entryProperty     = 0x0000
	entryVMK          = 0x0002
	entryFVEK         = 0x0003
	entryStartupKey   = 0x0006
	entryDescription  = 0x0007
	entryVolumeHeader = 0x000f
	entryVolumeGUID   = 0x0019

	valueKey          = 0x0001
	valueString       = 0x0002
	valueStretchKey   = 0x0003
	valueEncryptedKey = 0x0005
	valueExternalKey  = 0x0009
	valueGUID         = 0x0017
)

// Protection is how a volume master key protector is unlocked.
type Protection uint16

// The protections Windows writes (cryptsetup get_vmk_protection).
const (
	ClearKey         Protection = 0x0000
	TPM              Protection = 0x0100
	StartupKey       Protection = 0x0200
	TPMAndPIN        Protection = 0x0500
	RecoveryPassword Protection = 0x0800
	SmartCard        Protection = 0x1000
	Password         Protection = 0x2000
)

func (p Protection) String() string {
	switch p {
	case ClearKey:
		return "clear key"
	case TPM:
		return "TPM"
	case StartupKey:
		return "startup key"
	case TPMAndPIN:
		return "TPM and PIN"
	case RecoveryPassword:
		return "recovery password"
	case SmartCard:
		return "smart card"
	case Password:
		return "password"
	default:
		return "unknown"
	}
}

// Method is the volume's encryption method.
type Method uint16

// The six methods (cryptsetup BITLK_read_sb; libbde "Encryption methods").
const (
	AES128CBCElephant Method = 0x8000
	AES256CBCElephant Method = 0x8001
	AES128CBC         Method = 0x8002
	AES256CBC         Method = 0x8003
	AES128XTS         Method = 0x8004
	AES256XTS         Method = 0x8005
)

// String is cryptsetup's cipher-mode spelling.
func (m Method) String() string {
	switch m {
	case AES128CBCElephant, AES256CBCElephant:
		return "aes-cbc-elephant"
	case AES128CBC, AES256CBC:
		return "aes-cbc-eboiv"
	case AES128XTS, AES256XTS:
		return "aes-xts-plain64"
	default:
		return "unknown"
	}
}

// KeyBits is the length of the volume key, in bits, as cryptsetup counts
// it (the Elephant key included).
func (m Method) KeyBits() int {
	switch m {
	case AES128CBC:
		return 128
	case AES128CBCElephant, AES256CBC, AES128XTS:
		return 256
	case AES256CBCElephant, AES256XTS:
		return 512
	default:
		return 0
	}
}

// Protector is one volume master key protector.
type Protector struct {
	GUID       string
	Protection Protection

	salt      [16]byte
	hasSalt   bool
	clearKey  []byte // value 1, the key that opens a clear-key protector
	encrypted *ccmDatum
}

// ccmDatum is an AES-CCM encrypted key: nonce, tag, ciphertext.
type ccmDatum struct {
	nonce [nonceLen]byte
	tag   [tagLen]byte
	ct    []byte
}

// Info is what the metadata says, readable without any secret.
type Info struct {
	ToGo        bool
	Kind        Kind
	SectorSize  int
	VolumeSize  uint64 // the size the metadata records
	GUID        string // the volume identifier
	Method      Method
	Description string
	Protectors  []Protector
	// Normal reports that the volume is fully encrypted and not being
	// converted (current and next state both "encrypted").
	Normal bool
	// MetadataOffsets are the three 64 KiB metadata areas.
	MetadataOffsets [3]uint64
	// HeaderOffset and HeaderSize locate the encrypted copy of the original
	// first sectors of the volume.
	HeaderOffset uint64
	HeaderSize   uint64

	guid       [16]byte
	fvek       *ccmDatum
	validation ccmDatum
	digest     [32]byte // SHA-256 of the validated metadata block
}

// readInfo reads and checks the volume header and the first metadata copy
// whose CRC-32 matches (cryptsetup BITLK_read_sb). size is the device size.
func readInfo(r io.ReaderAt, size int64) (*Info, error) {
	sector := make([]byte, headerLen)
	if _, err := r.ReadAt(sector, 0); err != nil {
		return nil, ErrNotBitLocker
	}
	h, err := parseVolumeHeader(sector)
	if err != nil {
		return nil, err
	}
	block := make([]byte, metadataAreaSize)
	var blockLen int
	var val []byte
	idx := -1
	for i, off := range h.offsets {
		n, v, ok := readMetadataCopy(r, size, off, block)
		if ok {
			blockLen, val, idx = n, v, i
			break
		}
	}
	if idx < 0 {
		return nil, corrupt("no metadata copy passes its CRC-32")
	}
	block = block[:blockLen]
	in := &Info{ToGo: h.togo, Kind: h.kind, SectorSize: h.sectorSize}
	for i := range in.MetadataOffsets {
		in.MetadataOffsets[i] = binary.LittleEndian.Uint64(block[32+8*i:])
	}
	if in.MetadataOffsets[idx] != h.offsets[idx] {
		return nil, corrupt("metadata copy %d does not name its own offset", idx)
	}
	in.digest = sha256.Sum256(block)
	if err := parseValidation(val, &in.validation); err != nil {
		return nil, err
	}
	in.Normal = binary.LittleEndian.Uint16(block[12:]) == stateNormal &&
		binary.LittleEndian.Uint16(block[14:]) == stateNormal
	in.VolumeSize = binary.LittleEndian.Uint64(block[16:])
	copy(in.guid[:], block[blockHeaderLen+16:])
	in.GUID = formatGUID(in.guid[:])
	in.Method = Method(binary.LittleEndian.Uint16(block[blockHeaderLen+36:]))
	if in.Method.KeyBits() == 0 {
		return nil, unsupported("encryption method %#04x", uint16(in.Method))
	}
	msize := binary.LittleEndian.Uint32(block[blockHeaderLen:])
	if msize < metadataHeaderLen+4 || uint64(blockHeaderLen)+uint64(msize) > uint64(len(block)) {
		return nil, corrupt("metadata size %d in a block of %d", msize, len(block))
	}
	if err := in.parseEntries(block[blockHeaderLen+metadataHeaderLen : blockHeaderLen+int(msize)]); err != nil {
		return nil, err
	}
	if in.fvek == nil {
		return nil, corrupt("no encrypted volume key")
	}
	if in.HeaderSize == 0 {
		return nil, corrupt("no volume header entry")
	}
	return in, nil
}

// readMetadataCopy reads the metadata block at off into block and checks it
// against the CRC-32 of the validation record that follows it. It returns
// the block length and the validation record.
func readMetadataCopy(r io.ReaderAt, size int64, off uint64, block []byte) (int, []byte, bool) {
	if off > uint64(size) || uint64(size)-off < metadataAreaSize {
		return 0, nil, false
	}
	if _, err := r.ReadAt(block[:blockHeaderLen], int64(off)); err != nil {
		return 0, nil, false
	}
	if string(block[:8]) != string(signature) || binary.LittleEndian.Uint16(block[10:]) != metadataVersion2 {
		return 0, nil, false
	}
	n := int(binary.LittleEndian.Uint16(block[8:])) << 4
	// The validation record sits right after the block, inside the area.
	if n < blockHeaderLen+metadataHeaderLen || n+validationLen > metadataAreaSize {
		return 0, nil, false
	}
	if _, err := r.ReadAt(block[:n+validationLen], int64(off)); err != nil {
		return 0, nil, false
	}
	val := block[n : n+validationLen]
	vsize := binary.LittleEndian.Uint16(val[0:])
	vver := binary.LittleEndian.Uint16(val[2:])
	if vsize < 8 || vver > 2 {
		return 0, nil, false
	}
	if crc32.ChecksumIEEE(block[:n]) != binary.LittleEndian.Uint32(val[4:]) {
		return 0, nil, false
	}
	out := make([]byte, validationLen)
	copy(out, val)
	return n, out, true
}

// parseValidation decodes the AES-CCM datum of the validation record: with
// the volume master key it yields the SHA-256 of the metadata block
// (cryptsetup parse_fve_metadata_validation).
func parseValidation(v []byte, d *ccmDatum) error {
	if int(binary.LittleEndian.Uint16(v[0:])) < validationLen ||
		binary.LittleEndian.Uint16(v[8:]) != entryHeaderLen+validationDataLen ||
		binary.LittleEndian.Uint16(v[10:]) != 0 ||
		binary.LittleEndian.Uint16(v[12:]) != valueEncryptedKey {
		return corrupt("metadata validation record")
	}
	data := v[16 : 16+validationDataLen]
	copy(d.nonce[:], data)
	copy(d.tag[:], data[nonceLen:])
	d.ct = append([]byte(nil), data[nonceLen+tagLen:]...)
	return nil
}

// entry is one metadata entry: its header fields and its data (after the
// 8-byte header).
type entry struct {
	typ, value uint16
	data       []byte
}

// walkEntries calls f for every entry of b, refusing any entry whose size
// runs past b or cannot hold its own header. A zero size ends the list.
func walkEntries(b []byte, f func(entry) error) error {
	for len(b) >= 4 {
		size := int(binary.LittleEndian.Uint16(b))
		if size == 0 {
			return nil
		}
		if size < entryHeaderLen || size > len(b) {
			return corrupt("metadata entry of %d bytes with %d left", size, len(b))
		}
		e := entry{
			typ:   binary.LittleEndian.Uint16(b[2:]),
			value: binary.LittleEndian.Uint16(b[4:]),
			data:  b[entryHeaderLen:size],
		}
		if err := f(e); err != nil {
			return err
		}
		b = b[size:]
	}
	return nil
}

// parseCCM decodes an AES-CCM encrypted key entry's data.
func parseCCM(data []byte) (*ccmDatum, error) {
	if len(data) < nonceLen+tagLen {
		return nil, corrupt("encrypted key of %d bytes", len(data))
	}
	d := &ccmDatum{}
	copy(d.nonce[:], data)
	copy(d.tag[:], data[nonceLen:])
	d.ct = append([]byte(nil), data[nonceLen+tagLen:]...)
	return d, nil
}

func (in *Info) parseEntries(b []byte) error {
	return walkEntries(b, func(e entry) error {
		switch e.typ {
		case entryVMK:
			p, err := parseVMK(e.data)
			if err != nil {
				return err
			}
			in.Protectors = append(in.Protectors, p)
		case entryFVEK:
			if in.fvek != nil {
				return nil // cryptsetup keeps the first
			}
			d, err := parseCCM(e.data)
			if err != nil {
				return err
			}
			in.fvek = d
		case entryVolumeHeader:
			if len(e.data) < 16 {
				return corrupt("volume header entry of %d bytes", len(e.data))
			}
			in.HeaderOffset = binary.LittleEndian.Uint64(e.data)
			in.HeaderSize = binary.LittleEndian.Uint64(e.data[8:])
		case entryDescription:
			if in.Description == "" {
				in.Description = decodeUTF16(e.data)
			}
		}
		return nil
	})
}

// parseVMK decodes a volume master key entry: GUID, protection, then nested
// properties (cryptsetup parse_vmk_entry). Unknown nested values are skipped:
// every key that matters is authenticated by AES-CCM.
func parseVMK(data []byte) (Protector, error) {
	var p Protector
	if len(data) < vmkHeaderLen {
		return p, corrupt("volume master key entry of %d bytes", len(data))
	}
	p.GUID = formatGUID(data[:16])
	p.Protection = Protection(binary.LittleEndian.Uint16(data[26:]))
	err := walkEntries(data[vmkHeaderLen:], func(e entry) error {
		switch e.value {
		case valueStretchKey:
			if len(e.data) < 4+16 {
				return corrupt("stretch key of %d bytes", len(e.data))
			}
			copy(p.salt[:], e.data[4:])
			p.hasSalt = true
		case valueEncryptedKey:
			if p.encrypted != nil {
				return nil
			}
			d, err := parseCCM(e.data)
			if err != nil {
				return err
			}
			p.encrypted = d
		case valueKey:
			if len(e.data) < 4 {
				return corrupt("key of %d bytes", len(e.data))
			}
			if p.clearKey == nil {
				p.clearKey = append([]byte(nil), e.data[4:]...)
			}
		}
		return nil
	})
	return p, err
}

// decodeUTF16 decodes little-endian UTF-16, stopping at a NUL.
func decodeUTF16(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// ReadInfo reads the metadata of the BitLocker volume in r, of size bytes,
// without any secret: what cryptsetup bitlkDump prints.
func ReadInfo(r io.ReaderAt, size int64) (*Info, error) {
	return readInfo(r, size)
}
