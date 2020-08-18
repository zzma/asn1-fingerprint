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
	//TODO: fix this later - proper extension ASN.1 parsing
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

		if matchesTBSCertFormat(elements) {
			if c.ExcludeSubjNames {
				elements = append(elements[:5], elements[6:]...) // skip subject
				elements = append(elements[:3], elements[4:]...) // skip issuer
			} else {
				elements = append(elements[:3], elements[4:]...) // skip issuer
			}
		}

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
