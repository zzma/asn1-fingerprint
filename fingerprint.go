package asn1fp

import (
	"encoding/asn1"
	"errors"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

type Config struct {
	ExcludePrecert bool
	ParseOID       bool
	Strict         bool
	Log            *zap.SugaredLogger
}

func Fingerprint(bytes []byte, c *Config) (string, error) {
	var fp string
	//var obj asn1.RawValue
	//
	//if rest, err := asn1.Unmarshal(bytes, &obj); err != nil {
	//	return fp, err
	//} else if len(rest) != 0 {
	//	return fp, errors.New("extraneous ASN1 data")
	//}

	fps, err := fpRecurse(make([]int, 0), bytes, c)
	if err != nil {
		return fp, err
	}

	return strings.Join(fps, "|") + "\n", nil
}

func fpForChain(tagChain []int) string {
	strs := make([]string, len(tagChain))
	for i, v := range tagChain {
		strs[i] = strconv.Itoa(v)
	}
	return strings.Join(strs, ":")
}

func fpRecurse(tagChain []int, bytes []byte, c *Config) ([]string, error) {
	var obj asn1.RawValue

	rest, err := asn1.Unmarshal(bytes, &obj)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("fpRecurse: excess data")
	}

	c.Log.Debugf("Tags %s: %x", fpForChain(tagChain), bytes)

	fps := make([]string, 0)
	tagChain = append(tagChain, obj.Tag)

	if obj.IsCompound {
		//TODO: check for empty Sequence or Set
		elements, err := parseCompoundObj(obj.Bytes)
		if err != nil {
			c.Log.Fatal(err)
		}

		for _, element := range elements {
			paths, err := fpRecurse(tagChain, element.FullBytes, c)
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
		switch obj.Tag {
		case asn1.TagBoolean,
			asn1.TagInteger,
			asn1.TagBitString,
			asn1.TagOctetString,
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
			fps = append(fps, fpForChain(tagChain))
		case asn1.TagOID:
			if c.ExcludePrecert {
				oid, err := parseObjectIdentifier(obj.Bytes)
				if err != nil {
					return nil, err
				}
				if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
					return nil, &excludePrecertErr{}
				}
			}

			if c.ParseOID {
				oid, err := parseObjectIdentifier(obj.Bytes)
				if err != nil {
					return nil, err
				}
				fps = append(fps, fpForChain(tagChain)+"."+oid.String())
			} else {
				fps = append(fps, fpForChain(tagChain))
			}

		default:
			if c.Strict {
				c.Log.Errorf("invalid simple ASN1 type: %d", obj.Tag)
				return nil, errors.New("invalid ASN1 type")
			}

			fps = append(fps, fpForChain(tagChain))
		}
	}

	return fps, nil
}

type excludePrecertErr struct{}
func (e *excludePrecertErr) Error() string {
	return "found precert"
}