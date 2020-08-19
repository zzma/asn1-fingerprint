package asn1fp

import (
	"encoding/asn1"
	"errors"
	"github.com/prometheus/common/log"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

var (
	oidExtensionCTPrecertificatePoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtensionAuthorityInfoAccess            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionSubjectInfoAccess            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	oidExtensionSignedCertificateTimestampList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

type Config struct {
	IncludeExtensions bool
	ExcludeSubjNames  bool
	ExcludePrecert    bool
	ParseOID          bool
	Strict            bool
	Log               *zap.SugaredLogger
}

func Fingerprint(bytes []byte, c *Config) (string, error) {
	var fp string

	fps, err := fpRecurse(0, bytes, c)
	if err != nil {
		return fp, err
	}

	return strings.Join(fps, "\n") + "\n", nil
}

func fpForDepth(depth int, tag int) string {
	var str strings.Builder

	for i := 0; i < depth; i++ {
		str.WriteString("\t")
	}
	str.WriteString(strconv.Itoa(tag))

	return str.String()
}

const (
	SerialNumberTag = 2
	SignatureTag    = 16
	IssuerTag       = 16
	ValidityTag     = 16
	SubjectTag      = 16
	SpkiTag         = 16
)

//TODO: hacky way to check for subject / issuer name
func matchesTBSCertFormat(elements []*asn1.RawValue) bool {
	if len(elements) < 6 {
		return false
	}

	explicitVersion := elements[0].Tag == 0
	var indexOffset int
	if explicitVersion {
		indexOffset = 1
	} else {
		indexOffset = 0
	}

	if elements[0+indexOffset].Tag != SerialNumberTag {
		return false
	}

	if elements[1+indexOffset].Tag != SignatureTag {
		return false
	}

	if elements[2+indexOffset].Tag != IssuerTag {
		return false
	}
	if elements[3+indexOffset].Tag != ValidityTag {
		return false
	}

	if elements[4+indexOffset].Tag != SubjectTag {
		return false
	}

	if elements[5+indexOffset].Tag != SpkiTag {
		return false
	}

	return true
}

func parseOIDHandleBigInt(bytes []byte) (s asn1.ObjectIdentifier, err error) {
	oid, err := parseObjectIdentifier(bytes)

	if err == nil {
		return oid, nil
	}

	largeBase128Err := asn1.StructuralError{"base 128 integer too large"}
	if err == largeBase128Err {
		return asn1.ObjectIdentifier{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6}, nil
	}

	return oid, err

}

func fpRecurse(depth int, bytes []byte, c *Config) ([]string, error) {
	var obj asn1.RawValue

	rest, err := asn1.Unmarshal(bytes, &obj)
	if err != nil {
		return nil, err
	}

	if len(rest) > 0 && !c.IncludeExtensions {
		return nil, errors.New("fpRecurse: excess data")
	}

	fps := make([]string, 0)

	if obj.IsCompound {
		fps = append(fps, fpForDepth(depth, obj.Tag))

		//TODO: check for empty Sequence or Set
		elements, err := parseCompoundObj(obj.Bytes)
		if err != nil {
			c.Log.Fatal(err)
		}

		if depth == 1 && matchesTBSCertFormat(elements) {
			if c.ExcludeSubjNames {
				elements = append(elements[:5], elements[6:]...) // skip subject
				elements = append(elements[:3], elements[4:]...) // skip issuer
			} else {
				elements = append(elements[:3], elements[4:]...) // skip issuer
			}
		}

		// Detect extension object and handle each extension by OID
		if depth == 2 && obj.Tag == 3 && len(elements) == 1 && c.IncludeExtensions {
			extensions, err := parseCompoundObj(elements[0].Bytes)
			if err != nil {
				c.Log.Fatal(err)
			}

			for _, obj := range extensions {
				extension, err := parseCompoundObj(obj.Bytes)
				if err != nil {
					c.Log.Fatal(err)
				}
				extOID, err := parseOIDHandleBigInt(extension[0].Bytes)
				if err != nil {
					c.Log.Fatal(err)
				}

				if len(extOID) == 4 && extOID[0] == 2 && extOID[1] == 5 && extOID[2] == 29 {
					switch extOID[3] {
					case 35: // RFC 5280, 4.2.1.1. Authority Key Identifier
					case 14: // RFC 5280, 4.2.1.2. Subject Key Identifier
					case 15: // RFC 5280, 4.2.1.3. Key Usage
					case 32: // RFC 5280, 4.2.1.4. Certificate Policies
					case 33: // RFC 5280, 4.2.1.5. Policy Mappings
					case 17: // RFC 5280, 4.2.1.6. Subject Alternative Name
					case 18: // RFC 5280, 4.2.1.7. Issuer Alternative Name
					case 9: // RFC 5280, 4.2.1.8. Subject Directory Attributes
					case 19: // RFC 5280, 4.2.1.9. Basic Constraints
					case 30: // RFC 5280, 4.2.1.10. Name Constraints
					case 36: // RFC 5280, 4.2.1.11. Policy Constraints
					case 37: // RFC 5280, 4.2.1.12. Extended Key Usage
					case 31: // RFC 5280, 4.2.1.13. CRL Distribution Points
					case 54: // RFC 5280, 4.2.1.14. Inhibit anyPolicy
					case 46: // RFC 5280, 4.2.1.15. Freshest CRL (a.k.a. Delta CRL Distribution Point)
					default:

					}
				} else if extOID.Equal(oidExtensionAuthorityInfoAccess) {

				} else if extOID.Equal(oidExtensionSubjectInfoAccess) {

				} else if extOID.Equal(oidExtensionSignedCertificateTimestampList) {

				} else if extOID.Equal(oidExtensionCTPrecertificatePoison) {

				}
			}
		} else {
			for _, element := range elements {
				paths, err := fpRecurse(depth+1, element.FullBytes, c)
				if err != nil {
					switch err.(type) {
					case *excludePrecertErr:
						return nil, nil
					default:
						return nil, err
					}
				}

				fps = append(fps, paths...)
			}
		}

	} else {
		//	TODO: fix issue where GeneralName types [0-8] map to asn1 types in extensions
		switch obj.Tag {
		case asn1.TagBoolean,
			asn1.TagInteger,
			asn1.TagBitString,
			asn1.TagNull,
			asn1.TagEnum,
			asn1.TagUTF8String,
			asn1.TagNumericString,
			asn1.TagPrintableString,
			asn1.TagT61String,
			asn1.TagIA5String,
			asn1.TagUTCTime,
			asn1.TagGeneralizedTime,
			asn1.TagGeneralString:
			fps = append(fps, fpForDepth(depth, obj.Tag))
		case asn1.TagOctetString:
			if c.IncludeExtensions && depth == 5 { //TODO: fix this hack for parsing extensions
				paths, err := fpRecurse(depth+1, obj.Bytes, c)
				if err != nil {
					switch err.(type) {
					case *excludePrecertErr:
						return nil, nil
					default:
						return nil, err
					}
				}

				fps = append(fps, paths...)
			} else {
				fps = append(fps, fpForDepth(depth, obj.Tag))
			}

		case asn1.TagOID:
			oid, err := parseOIDHandleBigInt(obj.Bytes)
			if err != nil {
				return nil, err
			}

			if c.ExcludePrecert && oid.Equal(oidExtensionCTPrecertificatePoison) {
				return nil, &excludePrecertErr{}
			}

			if c.ParseOID {
				if len(oid) > 15 {
					log.Debug("Skipping super long OID, likely a IA5 General Name")
					fps = append(fps, fpForDepth(depth, obj.Tag))
					return fps, nil
				}

				fps = append(fps, fpForDepth(depth, obj.Tag)+"."+oid.String())
			} else {
				fps = append(fps, fpForDepth(depth, obj.Tag))
			}

		default:
			if c.Strict {
				c.Log.Errorf("invalid simple ASN1 type: %d", obj.Tag)
				return nil, errors.New("invalid ASN1 type")
			}

			fps = append(fps, fpForDepth(depth, obj.Tag))
		}
	}

	return fps, nil
}

type excludePrecertErr struct{}

func (e *excludePrecertErr) Error() string {
	return "found precert"
}
