package bitlocker

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-encryptions/ccm"
)

func unsupported(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, a...))
}

// kdfIterations is fixed by the format, not read from the volume: an image
// cannot ask for more work per protector, only for more protectors, which
// Limits.MaxKeyDerivations bounds.
const kdfIterations = 0x100000

// Limits bounds the work an untrusted image can ask for.
type Limits struct {
	// MaxKeyDerivations is how many protectors may run the key derivation
	// (2^20 SHA-256 each, about 0.1 s) before Open gives up with ErrLimit.
	MaxKeyDerivations int
}

// DefaultLimits allows 16 key derivations: Windows writes one per password
// or recovery password, and a volume rarely has more than three.
var DefaultLimits = Limits{MaxKeyDerivations: 16}

// stretch is BitLocker's key derivation (cryptsetup bitlk_kdf): 2^20 rounds
// of SHA-256 over {last, initial, salt, count}, count incremented each round.
func stretch(initial [32]byte, salt [16]byte) [32]byte {
	var rec [88]byte
	copy(rec[32:64], initial[:])
	copy(rec[64:80], salt[:])
	var last [32]byte
	for i := uint64(0); i < kdfIterations; i++ {
		binary.LittleEndian.PutUint64(rec[80:], i)
		last = sha256.Sum256(rec[:])
		copy(rec[:32], last[:])
	}
	return last
}

// passwordInitial is SHA-256(SHA-256(UTF-16LE(password))), no terminator.
// Like cryptsetup, the password ends at its first NUL; ok is false for
// input that is not UTF-8, which cryptsetup refuses for that protector.
func passwordInitial(pw []byte) (h [32]byte, ok bool) {
	if !utf8.Valid(pw) {
		return h, false
	}
	if i := bytes.IndexByte(pw, 0); i >= 0 {
		pw = pw[:i]
	}
	u := utf16.Encode([]rune(string(pw)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h = sha256.Sum256(b)
	return sha256.Sum256(h[:]), true
}

const (
	recoveryLen      = 55
	recoveryParts    = 8
	recoveryPartLen  = 6
	recoveryPartStep = recoveryPartLen + 1
)

// recoveryInitial parses a 48-digit recovery password (eight groups of six
// digits separated by '-', each a multiple of 11, one trailing newline
// allowed) and returns SHA-256 of the eight quotients as little-endian
// 16-bit words (cryptsetup get_recovery_key). ok is false for anything that
// is not a recovery password. A group of 720896 or more does not fit 16 bits:
// cryptsetup truncates it, this refuses it.
func recoveryInitial(s []byte) (h [32]byte, ok bool) {
	if len(s) == recoveryLen+1 && s[recoveryLen] == '\n' {
		s = s[:recoveryLen]
	}
	if len(s) != recoveryLen {
		return h, false
	}
	var key [2 * recoveryParts]byte
	for j := 0; j < recoveryParts; j++ {
		part := s[j*recoveryPartStep : j*recoveryPartStep+recoveryPartLen]
		if j < recoveryParts-1 && s[j*recoveryPartStep+recoveryPartLen] != '-' {
			return h, false
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return h, false
			}
			n = n*10 + int(c-'0')
		}
		if n%11 != 0 || n/11 > 0xffff {
			return h, false
		}
		binary.LittleEndian.PutUint16(key[2*j:], uint16(n/11))
	}
	return sha256.Sum256(key[:]), true
}

const (
	bekHeaderLen        = 48
	startupKeyHeaderLen = 24
)

// startupKey extracts the key of a .BEK file meant for the protector whose
// GUID is vmkGUID on the volume whose GUID is volGUID (cryptsetup
// get_startup_key, parse_external_key_entry). ok is false when the file is
// not a BEK file or is for another protector; err reports a BEK file for
// this protector that is malformed or for another volume.
func startupKey(b []byte, vmkGUID, volGUID string) (key []byte, ok bool, err error) {
	if len(b) < bekHeaderLen+entryHeaderLen {
		return nil, false, nil
	}
	if formatGUID(b[16:32]) != vmkGUID {
		return nil, false, nil
	}
	if v := binary.LittleEndian.Uint32(b[4:]); v != 1 {
		return nil, true, unsupported("startup key metadata version %d", v)
	}
	if binary.LittleEndian.Uint32(b[0:]) != uint32(len(b)) {
		return nil, true, corrupt("startup key size %d in a file of %d", binary.LittleEndian.Uint32(b[0:]), len(b))
	}
	e := b[bekHeaderLen:]
	if binary.LittleEndian.Uint16(e[2:]) != entryStartupKey || binary.LittleEndian.Uint16(e[4:]) != valueExternalKey {
		return nil, true, corrupt("startup key entry")
	}
	nested := bekHeaderLen + entryHeaderLen + startupKeyHeaderLen
	if nested > len(b) {
		return nil, true, corrupt("startup key entry")
	}
	err = walkEntries(b[nested:], func(e entry) error {
		if key != nil {
			return nil
		}
		if e.typ != entryProperty && e.typ != entryVolumeGUID {
			return corrupt("startup key entry type %#04x", e.typ)
		}
		switch e.value {
		case valueKey:
			if len(e.data) < 4 {
				return corrupt("startup key of %d bytes", len(e.data))
			}
			key = append([]byte(nil), e.data[4:]...)
		case valueString:
		case valueGUID:
			if len(e.data) < 16 {
				return corrupt("startup key volume GUID")
			}
			if g := formatGUID(e.data); g != volGUID {
				return corrupt("startup key is for volume %s, not %s", g, volGUID)
			}
		default:
			return corrupt("startup key entry value %#04x", e.value)
		}
		return nil
	})
	if err == nil && key == nil {
		err = corrupt("startup key holds no key")
	}
	return key, true, err
}

const keyMetadataLen = 12 // size u16, version u16, method u32... before the key

// openKey decrypts an AES-CCM key datum with key and returns the key
// material after its 12-byte header, checking the size the plaintext
// records against the ciphertext (cryptsetup decrypt_key). ok is false when
// the tag does not verify: the wrong key.
func openKey(key []byte, d *ccmDatum) (material []byte, ok bool, err error) {
	pt, ok := ccmOpen(key, d)
	if !ok {
		return nil, false, nil
	}
	if len(pt) < keyMetadataLen || int(binary.LittleEndian.Uint16(pt)) != len(d.ct) {
		return nil, true, corrupt("decrypted key records %d bytes for %d", binary.LittleEndian.Uint16(pt), len(d.ct))
	}
	return pt[keyMetadataLen:], true, nil
}

// ccmOpen is AES-CCM with a 12-byte nonce and a 16-byte tag, no additional
// data; on disk the tag comes before the ciphertext.
func ccmOpen(key []byte, d *ccmDatum) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, _ := ccm.NewCCM(block, tagLen, nonceLen) // fixed, valid sizes
	sealed := make([]byte, 0, len(d.ct)+tagLen)
	sealed = append(append(sealed, d.ct...), d.tag[:]...)
	pt, err := aead.Open(nil, d.nonce[:], sealed, nil)
	return pt, err == nil
}

// unlock finds the full-volume encryption key with secret (cryptsetup
// BITLK_get_volume_key): every protector is tried in metadata order with the
// interpretations of secret it accepts; a clear-key protector needs none.
func unlock(in *Info, secret []byte, lim Limits) ([]byte, error) {
	derivations := 0
	tried := false
	for i := range in.Protectors {
		p := &in.Protectors[i]
		var vmkKey []byte
		switch p.Protection {
		case ClearKey:
			if p.clearKey == nil || p.encrypted == nil {
				continue
			}
			vmkKey = p.clearKey
		case Password, RecoveryPassword:
			if secret == nil || !p.hasSalt || p.encrypted == nil {
				continue
			}
			var initial [32]byte
			var ok bool
			if p.Protection == Password {
				initial, ok = passwordInitial(secret)
			} else {
				initial, ok = recoveryInitial(secret)
			}
			if !ok {
				continue
			}
			if derivations >= lim.MaxKeyDerivations {
				return nil, fmt.Errorf("%w: more than %d key derivations", ErrLimit, lim.MaxKeyDerivations)
			}
			derivations++
			k := stretch(initial, p.salt)
			vmkKey = k[:]
		case StartupKey:
			if secret == nil || p.encrypted == nil {
				continue
			}
			k, ok, err := startupKey(secret, p.GUID, in.GUID)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			vmkKey = k
		default:
			continue
		}
		tried = true
		vmk, ok, err := openKey(vmkKey, p.encrypted)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if len(vmk) != 32 {
			return nil, corrupt("volume master key of %d bytes", len(vmk))
		}
		if err := in.checkDigest(vmk); err != nil {
			return nil, err
		}
		return in.fvekFrom(vmk)
	}
	if !tried {
		return nil, fmt.Errorf("%w: no protector accepts it (protectors: %s)", ErrWrongSecret, in.protectorList())
	}
	return nil, ErrWrongSecret
}

// checkDigest decrypts the validation record with the volume master key and
// compares the SHA-256 it holds with the metadata block's: the metadata is
// what Windows wrote, not only what passes a CRC-32.
func (in *Info) checkDigest(vmk []byte) error {
	pt, ok := ccmOpen(vmk, &in.validation)
	if !ok || len(pt) < 12+32 {
		return corrupt("the volume master key does not open the metadata validation record")
	}
	if binary.LittleEndian.Uint16(pt[2:]) != 0 || binary.LittleEndian.Uint16(pt[4:]) != 1 ||
		binary.LittleEndian.Uint16(pt[8:]) != 0x2005 {
		return unsupported("metadata validation hash type %#04x", binary.LittleEndian.Uint16(pt[8:]))
	}
	if !bytes.Equal(pt[12:44], in.digest[:]) {
		return corrupt("metadata SHA-256 does not match its validation record")
	}
	return nil
}

// fvekFrom decrypts the full-volume encryption key and lays it out as the
// sector cipher wants it: the data key, then the Elephant key if any.
func (in *Info) fvekFrom(vmk []byte) ([]byte, error) {
	kd, ok, err := openKey(vmk, in.fvek)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, corrupt("the volume master key does not open the volume key")
	}
	need := map[Method]int{
		AES128CBCElephant: 48, AES256CBCElephant: 64,
		AES128CBC: 16, AES256CBC: 32,
		AES128XTS: 32, AES256XTS: 64,
	}[in.Method]
	if len(kd) < need {
		return nil, corrupt("volume key of %d bytes for %s-%d", len(kd), in.Method, in.Method.KeyBits())
	}
	switch in.Method {
	case AES128CBCElephant:
		// 16-byte CBC key, 16 unused, 16-byte Elephant key, 16 unused.
		return append(append([]byte(nil), kd[:16]...), kd[32:48]...), nil
	default:
		return append([]byte(nil), kd[:need]...), nil
	}
}
