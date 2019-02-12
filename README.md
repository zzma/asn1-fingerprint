# asn1-fingerprint
Structural fingerprinting for ASN.1 objects

## Usage
```
asn1-fingerprint: structural fingerprints of ASN.1 data

usage: ./asn1-fingerprint -i <input file/directory> -o <output file>

Options:
  -f string
        input data encoding format (base64, hex) (default "base64")
  -i string
        input file/directory path
  -o string
        output file path (default "-")
  -oid
        parse and use oids in fingerprinting
  -profile
        run performance profiler
  -r    search input directory recursively
  -rotate
        rotate output file
  -rotate-size int
        size threshold for output file rotation (default 5000000000)
  -v    verbose debug output
  -workers int
        number of parallel parsers (one per file) (default 8)
```
