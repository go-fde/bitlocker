# bitlocker

Read BitLocker (BDE) encrypted volumes in pure Go: unlock with a password, a
recovery password, a startup key (`.BEK` file) or a clear key, and read the
decrypted volume through an `io.ReaderAt`.

```go
dev, err := bitlocker.Open("volume.img", []byte("password"))
if err != nil {
	log.Fatal(err)
}
defer dev.Close()

boot := make([]byte, 512)
_, err = dev.ReadAt(boot, 0) // the NTFS / exFAT / FAT boot sector
```

`OpenFrom(r, size, secret, limits)` reads from any `io.ReaderAt` (a
partition, a QCOW2 disk), and `ReadInfo(r, size)` reads the metadata without
a secret: GUID, method, protectors, description, the same fields as
`cryptsetup bitlkDump`.

## What it reads

| | |
|---|---|
| Volumes | Windows 7 and later, BitLocker To Go |
| Methods | AES-CBC 128/256 with and without the Elephant diffuser, AES-XTS 128/256 |
| Sectors | 512 bytes and 4 KiB |
| Protectors | password, recovery password, startup key (`.BEK`), clear key (suspended protection) |

The secret is interpreted the way cryptsetup interprets it: as a password,
as a recovery password when it has the 48-digit shape, as a `.BEK` file for
startup-key protectors. A clear-key protector opens with any secret, `nil`
included.

**Refused with `ErrUnsupported`** (their metadata still reads): Windows Vista
metadata, encrypt-on-write ("used space only") volumes, and volumes in the
middle of an encryption or decryption. These are the volumes cryptsetup
does not activate either. TPM and smart-card protectors need hardware.
**Writing** is not implemented: `WriteAt` returns `ErrReadOnly`.

## How it is checked

The decrypted device is the one `cryptsetup bitlkOpen` maps, byte for byte:
the first sectors are read from their encrypted copy, and the three metadata
areas and that copy's location read as zeros.

The tests open the 21 volumes in cryptsetup's `tests/bitlk-images.tar.xz`,
which Windows made. Each volume is opened with every secret its
`images.conf` lists: password, Unicode password, one or two recovery
passwords, startup key, clear key. The test then compares:

- the SHA-256 of the whole decrypted device with cryptsetup's;
- the file system UUID with blkid's;
- every protector GUID with the reference.

The two volumes cryptsetup refuses (partially encrypted, encrypt-on-write)
must be refused here as well. The archive is GPL-2.0+, so it is fetched at
test time (pinned by commit and SHA-256), never committed:

```sh
BITLK_IMAGES=/path/to/bitlk-images.tar.xz go test ./...
```

Without it the interoperability test skips and says so. Unit tests write
their own volumes to reach every refusal. CI runs with the archive and
requires 100% coverage.

## Untrusted images

- Every offset and size the image declares is checked against the device.
  Regions that leave the device, are not sector-aligned, or overlap are
  refused.
- A metadata copy is used only if it passes its CRC-32. Once the volume
  master key is open, the metadata is also authenticated: the AES-CCM
  validation record must hold the SHA-256 of the metadata block.
- The key derivation is fixed by the format (2²⁰ rounds of SHA-256, about
  0.1 s), so an image cannot make one derivation cost more. It can list
  many protectors, so `Limits.MaxKeyDerivations` (16 by default) bounds
  their number and returns `ErrLimit` beyond it.
- The parsers are fuzzed (`FuzzOpen`, `FuzzStartupKey`,
  `FuzzRecoveryPassword`), and `govulncheck` runs in CI.

## Performance

`ReadAt` makes two allocations per call, whatever the length. A
sector-aligned read decrypts in the caller's buffer.

The table below was measured on one Apple M4 Max core, reading 1 MiB per
call from 512-byte-sector volumes, in two interleaved rounds. The
reference is OpenSSL 3.6.5 on the same core (`openssl speed -seconds 2
-bytes 512 -evp …`):

| Method | this package | OpenSSL | |
|---|---|---|---|
| AES-128-XTS | 7.5 GB/s | 12.9 GB/s | per-sector cost in xts: go-encryptions/xts#16 |
| AES-256-XTS | 6.5 GB/s | — | |
| AES-128-CBC | 2.1 GB/s | 21.0 GB/s (4 KiB) | one block at a time: #2 |
| AES-128-CBC + Elephant | 0.40 GB/s | no equivalent | dm-crypt's diffuser is kernel C, not measurable on macOS |
| Key derivation (2²⁰ SHA-256) | 67 ms | ≈ 100 ms (2²⁰ × `openssl speed sha256` at 64 bytes) | |

Every row below OpenSSL is an open defect, linked in the table.

## References

- cryptsetup `lib/bitlk/bitlk.c`: metadata, key chain and the device-mapper
  layout this package reproduces.
- Linux `drivers/md/dm-crypt.c`: `eboiv` and the Elephant diffuser, ported
  index for index.
- [libbde format documentation](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)
  and [dislocker](https://github.com/Aorimn/dislocker).

## Licence

BSD-3-Clause. The test corpus is cryptsetup's (GPL-2.0+) and is not part of
this repository.
