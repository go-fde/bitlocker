package bitlocker

import (
	"bytes"
	"testing"
)

// Reference for the sector benchmarks: OpenSSL's AES-XTS / AES-CBC on the
// same machine, single core (`openssl speed -evp aes-128-xts -bytes 4096`);
// BitLocker adds an IV encryption per sector (CBC) and the Elephant
// diffuser, which no hardware instruction helps.

func benchDevice(b *testing.B, m Method) *Device {
	s := defaultSpec()
	s.size = 4 << 20
	s.method = m
	s.protectors = []protSpec{{prot: ClearKey, guid: [16]byte{4}, clearKey: bytes.Repeat([]byte{0x24}, 32)}}
	img, _ := buildImage(b, s)
	d, err := OpenFrom(memDev{bytes.NewReader(img)}, int64(len(img)), nil, DefaultLimits)
	if err != nil {
		b.Fatal(err)
	}
	return d
}

func benchRead(b *testing.B, m Method) {
	d := benchDevice(b, m)
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.ReadAt(buf, 1<<20); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadXTS128(b *testing.B)      { benchRead(b, AES128XTS) }
func BenchmarkReadXTS256(b *testing.B)      { benchRead(b, AES256XTS) }
func BenchmarkReadCBC128(b *testing.B)      { benchRead(b, AES128CBC) }
func BenchmarkReadElephant128(b *testing.B) { benchRead(b, AES128CBCElephant) }

// BenchmarkKeyDerivation is the 2^20-round SHA-256 every password or
// recovery password costs; cryptsetup runs the same loop through OpenSSL.
func BenchmarkKeyDerivation(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		stretch([32]byte{1}, [16]byte{2})
	}
}
