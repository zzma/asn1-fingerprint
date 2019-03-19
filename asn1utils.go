/* mostly borrowed from https://github.com/golang/go/tree/master/src/encoding/asn1  */

package asn1fp

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

type asteriskFlag bool
type ampersandFlag bool

const (
	allowAsterisk  asteriskFlag = true
	rejectAsterisk asteriskFlag = false

	allowAmpersand  ampersandFlag = true
	rejectAmpersand ampersandFlag = false
)

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// If asterisk is allowAsterisk then '*' is also allowed, reflecting existing
// practice. If ampersand is allowAmpersand then '&' is allowed as well.
func isPrintable(b byte, asterisk asteriskFlag, ampersand ampersandFlag) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
	// This is technically not allowed in a PrintableString.
	// However, x509 certificates with wildcard strings don't
	// always use the correct string type so we permit it.
		(bool(asterisk) && b == '*') ||
	// This is not technically allowed either. However, not
	// only is it relatively common, but there are also a
	// handful of CA certificates that contain it. At least
	// one of which will not expire until 2027.
		(bool(ampersand) && b == '&')
}

// PrintableString

// parsePrintableString parses an ASN.1 PrintableString from the given byte
// array and returns it.
func parsePrintableString(bytes []byte) (ret string, err error) {
	for _, b := range bytes {
		if !isPrintable(b, allowAsterisk, allowAmpersand) {
			err = asn1.SyntaxError{"PrintableString contains invalid character"}
			return
		}
	}
	ret = string(bytes)
	return
}

// IA5String

// parseIA5String parses an ASN.1 IA5String (ASCII string) from the given
// byte slice and returns it.
func parseIA5String(bytes []byte) (ret string, err error) {
	for _, b := range bytes {
		if b >= utf8.RuneSelf {
			err = asn1.SyntaxError{"IA5String contains invalid character"}
			return
		}
	}
	ret = string(bytes)
	return
}

// T61String

// parseT61String parses an ASN.1 T61String (8-bit clean string) from the given
// byte slice and returns it.
func parseT61String(bytes []byte) (ret string, err error) {
	return string(bytes), nil
}

// UTF8String

// parseUTF8String parses an ASN.1 UTF8String (raw UTF-8) from the given byte
// array and returns it.
func parseUTF8String(bytes []byte) (ret string, err error) {
	if !utf8.Valid(bytes) {
		return "", errors.New("asn1: invalid UTF-8 string")
	}
	return string(bytes), nil
}

// NumericString

// parseNumericString parses an ASN.1 NumericString from the given byte array
// and returns it.
func parseNumericString(bytes []byte) (ret string, err error) {
	for _, b := range bytes {
		if !isNumeric(b) {
			return "", asn1.SyntaxError{"NumericString contains invalid character"}
		}
	}
	return string(bytes), nil
}

// isNumeric reports whether the given b is in the ASN.1 NumericString set.
func isNumeric(b byte) bool {
	return '0' <= b && b <= '9' ||
		b == ' '
}

// INTEGER

// checkInteger returns nil if the given bytes are a valid DER-encoded
// INTEGER and an error otherwise.
func checkInteger(bytes []byte) error {
	if len(bytes) == 0 {
		return asn1.StructuralError{"empty integer"}
	}
	if len(bytes) == 1 {
		return nil
	}
	if (bytes[0] == 0 && bytes[1]&0x80 == 0) || (bytes[0] == 0xff && bytes[1]&0x80 == 0x80) {
		return asn1.StructuralError{"integer not minimally-encoded"}
	}
	return nil
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
	err = checkInteger(bytes)
	if err != nil {
		return
	}
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		err = asn1.StructuralError{"integer too large"}
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8
	ret >>= 64 - uint8(len(bytes))*8
	return
}

// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
func parseBitString(bytes []byte) (ret asn1.BitString, err error) {
	if len(bytes) == 0 {
		err = asn1.SyntaxError{"zero length BIT STRING"}
		return
	}
	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = asn1.SyntaxError{"invalid padding bits in BIT STRING"}
		return
	}
	ret.BitLength = (len(bytes)-1)*8 - paddingBits
	ret.Bytes = bytes[1:]
	return
}

// parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// returns it. An object identifier is a sequence of variable length integers
// that are assigned in a hierarchy.
func parseObjectIdentifier(bytes []byte) (s asn1.ObjectIdentifier, err error) {
	if len(bytes) == 0 {
		err = asn1.SyntaxError{"zero length OBJECT IDENTIFIER"}
		return
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	s = make([]int, len(bytes)+1)

	// The first varint is 40*value1 + value2:
	// According to this packing, value1 can take the values 0, 1 and 2 only.
	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
	// then there are no restrictions on value2.
	v, offset, err := parseBase128Int(bytes, 0)
	if err != nil {
		return
	}
	if v < 80 {
		s[0] = v / 40
		s[1] = v % 40
	} else {
		s[0] = 2
		s[1] = v - 80
	}

	i := 2
	for ; offset < len(bytes); i++ {
		v, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		s[i] = v
	}
	s = s[0:i]
	return
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	var ret64 int64
	for shifted := 0; offset < len(bytes); shifted++ {
		// 5 * 7 bits per byte == 35 bits of data
		// Thus the representation is either non-minimal or too large for an int32
		if shifted == 5 {
			err = asn1.StructuralError{"base 128 integer too large"}
			return
		}
		ret64 <<= 7
		b := bytes[offset]
		ret64 |= int64(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			ret = int(ret64)
			// Ensure that the returned value fits in an int on all platforms
			if ret64 > math.MaxInt32 {
				err = asn1.StructuralError{"base 128 integer too large"}
			}
			return
		}
	}
	err = asn1.SyntaxError{"truncated base 128 integer"}
	return
}

// UTCTime

func parseUTCTime(bytes []byte) (ret time.Time, err error) {
	s := string(bytes)

	formatStr := "0601021504Z0700"
	ret, err = time.Parse(formatStr, s)
	if err != nil {
		formatStr = "060102150405Z0700"
		ret, err = time.Parse(formatStr, s)
	}
	if err != nil {
		return
	}

	if serialized := ret.Format(formatStr); serialized != s {
		err = fmt.Errorf("asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q", s, serialized)
		return
	}

	if ret.Year() >= 2050 {
		// UTCTime only encodes times prior to 2050. See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
		ret = ret.AddDate(-100, 0, 0)
	}

	return
}

// parseGeneralizedTime parses the GeneralizedTime from the given byte slice
// and returns the resulting time.
func parseGeneralizedTime(bytes []byte) (ret time.Time, err error) {
	const formatStr = "20060102150405Z0700"
	s := string(bytes)

	if ret, err = time.Parse(formatStr, s); err != nil {
		return
	}

	if serialized := ret.Format(formatStr); serialized != s {
		err = fmt.Errorf("asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q", s, serialized)
	}

	return
}

// Tagging

type tagAndLength struct {
	class, tag, length int
	isCompound         bool
}

// parseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func parseTagAndLength(bytes []byte, initOffset int) (ret tagAndLength, offset int, err error) {
	offset = initOffset
	// parseTagAndLength should not be called without at least a single
	// byte to read. Thus this check is for robustness:
	if offset >= len(bytes) {
		err = errors.New("asn1: internal error in parseTagAndLength")
		return
	}
	b := bytes[offset]
	offset++
	ret.class = int(b >> 6)
	ret.isCompound = b&0x20 == 0x20
	ret.tag = int(b & 0x1f)

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterwards
	if ret.tag == 0x1f {
		ret.tag, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		// Tags should be encoded in minimal form.
		if ret.tag < 0x1f {
			err = asn1.SyntaxError{"non-minimal tag"}
			return
		}
	}
	if offset >= len(bytes) {
		err = asn1.SyntaxError{"truncated tag or length"}
		return
	}
	b = bytes[offset]
	offset++
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = asn1.SyntaxError{"indefinite length found (not DER)"}
			return
		}
		ret.length = 0
		for i := 0; i < numBytes; i++ {
			if offset >= len(bytes) {
				err = asn1.SyntaxError{"truncated tag or length"}
				return
			}
			b = bytes[offset]
			offset++
			if ret.length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = asn1.StructuralError{"length too large"}
				return
			}
			ret.length <<= 8
			ret.length |= int(b)
			if ret.length == 0 {
				// DER requires that lengths be minimal.
				err = asn1.StructuralError{"superfluous leading zeros in length"}
				return
			}
		}
		// Short lengths must be encoded in short form.
		if ret.length < 0x80 {
			err = asn1.StructuralError{"non-minimal length"}
			return
		}
	}

	return
}

// invalidLength returns true iff offset + length > sliceLength, or if the
// addition would overflow.
func invalidLength(offset, length, sliceLength int) bool {
	return offset+length < offset || offset+length > sliceLength
}

// parseCompoundObj is used for SEQUENCE OF and SET OF values. It tries to parse
// a number of ASN.1 values from the given byte slice and returns them as a
// slice of Go values of the given type.
func parseCompoundObj(bytes []byte) (ret []*asn1.RawValue, err error) {
	ret = make([]*asn1.RawValue, 0)

	numElements := 0
	for offset := 0; offset < len(bytes); {
		var t tagAndLength
		oldOffset := offset
		t, offset, err = parseTagAndLength(bytes, offset)
		if err != nil {
			return
		}

		if invalidLength(offset, t.length, len(bytes)) {
			err = asn1.SyntaxError{"truncated sequence"}
			return
		}

		obj := asn1.RawValue{
			Class:      t.class,
			Tag:        t.tag,
			IsCompound: t.isCompound,
			Bytes:      bytes[offset : offset+t.length],
			FullBytes:  bytes[oldOffset : offset+t.length],
		}

		ret = append(ret, &obj)

		offset += t.length
		numElements++
	}

	return
}

// BOOLEAN

func parseBool(bytes []byte) (ret bool, err error) {
	if len(bytes) != 1 {
		err = asn1.SyntaxError{"invalid boolean"}
		return
	}

	// DER demands that "If the encoding represents the boolean value TRUE,
	// its single contents octet shall have all eight bits set to one."
	// Thus only 0 and 255 are valid encoded values.
	switch bytes[0] {
	case 0:
		ret = false
	case 0xff:
		ret = true
	default:
		err = asn1.SyntaxError{"invalid boolean"}
	}

	return
}
