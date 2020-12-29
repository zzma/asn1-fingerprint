# asn1-fingerprint
Structural fingerprinting for ASN.1 objects

## Usage
```
asn1-fingerprint: structural fingerprints of ASN.1 data

usage: ./asn1-fp -i <input file/directory> -o <output file>

Options:
  -d string
    	delimiter for asn1 data (default ",")
  -exclude-precert
    	exclude precert
  -exclude-subj
    	exclude subject name for the cert
  -f int
    	column that contains asn1 data (default 1)
  -format string
    	input data encoding format (base64, hex) (default "base64")
  -i string
    	input file/directory path
  -include-extensions
    	include extension parsing
  -o string
    	output file path (default "-")
  -oid
    	parse and use OIDs in fingerprinting
  -profile
    	run performance profiler
  -r	search input directory recursively
  -rotate
    	rotate output file
  -rotate-size int
    	size threshold for output file rotation (default 5000000000)
  -strict
    	fail if there are asn1 parsing errors
  -v	verbose debug output
  -workers int
    	number of parallel parsers (one per file) (default 8)
```
