package bitlocker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Errors. Every error this package returns for a malformed image wraps
// ErrCorrupt; the others are distinct and work with errors.Is.
var (
	// ErrNotBitLocker means the volume header carries neither BitLocker
	// signature: the device is not a BitLocker volume.
	ErrNotBitLocker = errors.New("bitlocker: not a BitLocker volume")
	// ErrCorrupt wraps every refusal of a malformed or inconsistent image.
	ErrCorrupt = errors.New("bitlocker: corrupt volume")
	// ErrUnsupported is a well-formed volume this package does not open:
	// Windows Vista (version 1) metadata, encrypt-on-write ("used space
	// only") volumes, volumes being encrypted or decrypted, unknown methods.
	ErrUnsupported = errors.New("bitlocker: unsupported volume")
	// ErrWrongSecret means no protector of the volume opened with the
	// secret given.
	ErrWrongSecret = errors.New("bitlocker: no protector opened with this secret")
	// ErrLimit means the volume asked for more key derivations than the
	// Limits allow before one opened.
	ErrLimit = errors.New("bitlocker: limit exceeded")
	// ErrReadOnly is returned by WriteAt: this version only reads.
	ErrReadOnly = errors.New("bitlocker: read-only")
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

// Volume header constants (cryptsetup lib/bitlk/bitlk.c; libbde "Volume
// header").
const (
	headerLen         = 512
	signatureOff      = 3
	sectorSizeOff     = 11
	superblockOff     = 160 // GUID then three metadata offsets
	superblockOffToGo = 424
	metadataAreaSize  = 64 << 10
	blockHeaderLen    = 64
	metadataHeaderLen = 48
	entryHeaderLen    = 8
	vmkHeaderLen      = 28
	validationLen     = 88
	validationDataLen = 72
	nonceLen          = 12
	tagLen            = 16
	stateNormal       = 0x0004
	metadataVersion2  = 2
)

var (
	signature     = []byte("-FVE-FS-")
	signatureToGo = []byte("MSWIN4.1")
	bootCodeV1    = []byte{0xeb, 0x52, 0x90} // Windows Vista
	bootCodeV2    = []byte{0xeb, 0x58, 0x90}

	// guidNormal and guidEOW are the on-disk bytes of the BitLocker
	// identifiers 4967d63b-2e29-4ad8-8399-f6a339e3d001 and
	// 92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8 ("encrypt on write").
	guidNormal = [16]byte{0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01}
	guidEOW    = [16]byte{0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8}
)

// Kind is the encryption kind the volume header names.
type Kind int

const (
	// Normal is a volume whose every sector is encrypted.
	Normal Kind = iota
	// EncryptOnWrite is a "used space only" volume: free space was never
	// encrypted. Its metadata reads; it does not open.
	EncryptOnWrite
	// UnknownKind is any other identifier in the volume header.
	UnknownKind
)

func (k Kind) String() string {
	switch k {
	case Normal:
		return "normal"
	case EncryptOnWrite:
		return "encrypt-on-write"
	default:
		return "unknown"
	}
}

// volumeHeader is what sector 0 tells before any metadata is read.
type volumeHeader struct {
	togo       bool
	sectorSize int
	kind       Kind
	offsets    [3]uint64
}

// isBitLocker reports whether the first 512 bytes carry a BitLocker
// signature. A To Go volume's "MSWIN4.1" is also what plain FAT32 writes, so
// it counts only with a BitLocker identifier at offset 424.
func isBitLocker(b []byte) bool {
	if len(b) < headerLen {
		return false
	}
	sig := b[signatureOff : signatureOff+8]
	if bytes.Equal(sig, signature) {
		return true
	}
	if bytes.Equal(sig, signatureToGo) {
		var g [16]byte
		copy(g[:], b[superblockOffToGo:])
		return g == guidNormal || g == guidEOW
	}
	return false
}

// Detect reports whether r begins with a BitLocker volume header. It reads
// 512 bytes and never returns an error for a short or unreadable device: such
// a device is not BitLocker.
func Detect(r io.ReaderAt) bool {
	b := make([]byte, headerLen)
	n, _ := r.ReadAt(b, 0)
	return isBitLocker(b[:n])
}

// parseVolumeHeader decodes sector 0 (cryptsetup BITLK_read_sb, before the
// metadata loop).
func parseVolumeHeader(b []byte) (volumeHeader, error) {
	var h volumeHeader
	if len(b) < headerLen {
		return h, ErrNotBitLocker
	}
	sb := superblockOff
	switch sig := b[signatureOff : signatureOff+8]; {
	case bytes.Equal(sig, signature):
	case bytes.Equal(sig, signatureToGo):
		h.togo = true
		sb = superblockOffToGo
	default:
		return h, ErrNotBitLocker
	}
	switch code := b[:3]; {
	case bytes.Equal(code, bootCodeV2):
	case bytes.Equal(code, bootCodeV1):
		return h, fmt.Errorf("%w: Windows Vista (version 1) metadata", ErrUnsupported)
	default:
		return h, corrupt("unknown boot code % x", code)
	}
	h.sectorSize = int(binary.LittleEndian.Uint16(b[sectorSizeOff:]))
	if h.sectorSize == 0 {
		h.sectorSize = 512
	}
	if h.sectorSize != 512 && h.sectorSize != 4096 {
		return h, corrupt("sector size %d", h.sectorSize)
	}
	var g [16]byte
	copy(g[:], b[sb:])
	switch g {
	case guidNormal:
		h.kind = Normal
	case guidEOW:
		h.kind = EncryptOnWrite
	default:
		h.kind = UnknownKind
	}
	for i := range h.offsets {
		h.offsets[i] = binary.LittleEndian.Uint64(b[sb+16+8*i:])
	}
	return h, nil
}

// formatGUID renders a Windows GUID (first three fields little-endian) the
// way cryptsetup and Windows print it, in lower case.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10], b[10:16])
}
