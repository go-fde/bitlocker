// Package bitlocker reads BitLocker (BDE) encrypted volumes in pure Go.
//
// It unlocks a volume made by Windows 7 or later, including BitLocker To Go,
// with a password, a recovery password, a startup key (.BEK file) or a clear
// key, and exposes the decrypted volume as an io.ReaderAt. All six methods
// are read: AES-CBC 128/256 with and without the Elephant diffuser, and
// AES-XTS 128/256, on 512-byte and 4 KiB sectors.
//
// The decrypted device is the one cryptsetup's bitlkOpen maps, byte for
// byte: the original first sectors are read from their encrypted copy, the
// three metadata areas and that copy's location read as zeros. The tests
// compare SHA-256 sums with cryptsetup's on volumes Windows made.
//
// # Usage
//
//	dev, err := bitlocker.Open("/path/to/volume.img", []byte("password"))
//	if err != nil { log.Fatal(err) }
//	defer dev.Close()
//	buf := make([]byte, 512)
//	_, err = dev.ReadAt(buf, 0) // the NTFS or FAT boot sector
//
// The secret is interpreted as cryptsetup interprets it: as a password for
// password protectors, as a recovery password ("123456-…", 48 digits) for
// recovery protectors when it has that shape, and as the contents of a .BEK
// file for startup-key protectors. A clear-key protector (a volume whose
// protection is suspended) opens with any secret, nil included.
//
// # Not supported
//
// Windows Vista metadata, encrypt-on-write ("used space only") volumes and
// volumes in the middle of an encryption or decryption are refused with
// ErrUnsupported; their metadata still reads with ReadInfo. TPM and smart
// card protectors need hardware. Writing is not implemented: WriteAt returns
// ErrReadOnly.
//
// # Untrusted images
//
// Every offset and size an image declares is checked against the device
// before use, the metadata is authenticated with the volume master key
// (AES-CCM, then SHA-256 of the metadata block), and Limits bounds how many
// 2^20-round key derivations an image with many protectors can ask for.
package bitlocker

import (
	"fmt"
	"io"
	"os"
)

// ReadAtCloser is what OpenFrom reads the encrypted volume from.
type ReadAtCloser interface {
	io.ReaderAt
	io.Closer
}

// Device is an unlocked BitLocker volume. ReadAt is safe for concurrent use.
type Device struct {
	r      ReadAtCloser
	info   *Info
	layout layout
	c      sectorCipher
	ss     uint64
	key    []byte // the sector key, kept for tests to compare unlock paths
}

// fileSize is replaceable so that a test can make it fail.
var fileSize = func(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Open opens the BitLocker volume at path read-only and unlocks it with
// secret. A block device's size is not what Stat reports on every system:
// open one with OpenFrom and its size.
func Open(path string, secret []byte) (*Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bitlocker: %w", err)
	}
	size, err := fileSize(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("bitlocker: %w", err)
	}
	d, err := OpenFrom(f, size, secret, DefaultLimits)
	if err != nil {
		f.Close()
		return nil, err
	}
	return d, nil
}

// OpenFrom unlocks the BitLocker volume of size bytes in r with secret.
// Close on the returned Device closes r.
func OpenFrom(r ReadAtCloser, size int64, secret []byte, lim Limits) (*Device, error) {
	if size < 0 {
		return nil, fmt.Errorf("bitlocker: negative size %d", size)
	}
	in, err := readInfo(r, size)
	if err != nil {
		return nil, err
	}
	if in.Kind != Normal {
		return nil, unsupported("%s volume", in.Kind)
	}
	if !in.Normal {
		return nil, unsupported("volume is being encrypted or decrypted")
	}
	ss := uint64(in.SectorSize)
	// The mapped device is the whole device in whole sectors, as
	// device-mapper sees it.
	usize := uint64(size) / ss * ss
	l, err := newLayout(in, usize)
	if err != nil {
		return nil, err
	}
	key, err := unlock(in, secret, lim)
	if err != nil {
		return nil, err
	}
	// It cannot fail: readInfo refused unknown methods, and fvekFrom
	// returns exactly the key length the method takes.
	c, _ := newSectorCipher(in.Method, key, in.SectorSize)
	return &Device{r: r, info: in, layout: l, c: c, ss: ss, key: key}, nil
}

// Info returns the volume's metadata.
func (d *Device) Info() *Info { return d.info }

// Size is the length of the decrypted volume in bytes.
func (d *Device) Size() int64 { return int64(d.layout.size) }

// Close closes the underlying reader.
func (d *Device) Close() error { return d.r.Close() }

// WriteAt is not implemented.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	return 0, ErrReadOnly
}

// ReadAt reads the decrypted volume at off.
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("bitlocker: negative offset %d", off)
	}
	size := d.layout.size
	if uint64(off) >= size {
		return 0, io.EOF
	}
	want := len(p)
	if rest := size - uint64(off); uint64(want) > rest {
		want = int(rest)
	}
	ss := d.ss
	first := uint64(off) / ss * ss
	end := (uint64(off) + uint64(want) + ss - 1) / ss * ss
	// A read of whole sectors decrypts in the caller's buffer.
	var buf []byte
	if first == uint64(off) && end-first == uint64(want) {
		buf = p[:want]
	} else {
		buf = make([]byte, end-first)
	}
	scratch := newScratch(int(ss))
	// Runs of sectors that map contiguously are read with one ReadAt.
	for pos := first; pos < end; {
		reg := d.layout.locate(pos)
		runEnd := end
		var src uint64
		zero := false
		if reg != nil {
			runEnd = min(runEnd, reg.end)
			zero = reg.zero
			src = reg.src + (pos - reg.start)
		} else {
			// An identity run stops at the next region.
			for _, r := range d.layout.regions {
				if r.start > pos && r.start < runEnd {
					runEnd = r.start
				}
			}
			src = pos
		}
		chunk := buf[pos-first : runEnd-first]
		if zero {
			clear(chunk)
		} else {
			if n, err := d.r.ReadAt(chunk, int64(src)); n < len(chunk) {
				return 0, fmt.Errorf("bitlocker: read at %d: %w", src, err)
			}
			d.c.decrypt(chunk, src, scratch)
		}
		pos = runEnd
	}
	n := copy(p, buf[uint64(off)-first:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (in *Info) protectorList() string {
	s := ""
	for i, p := range in.Protectors {
		if i > 0 {
			s += ", "
		}
		s += p.Protection.String()
	}
	if s == "" {
		return "none"
	}
	return s
}
