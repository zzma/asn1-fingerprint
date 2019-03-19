package main

import (
	"errors"
	"github.com/zzma/asn1-fingerprint"
)

type InputFormat int

const (
	FormatBase64 = InputFormat(iota)
	FormatHex
)

type config struct {
	verbose bool
	profile bool

	inputPath      string
	inputFormatStr string
	inputFormat    InputFormat
	recursiveDir   bool

	delimiter string
	asn1Col   int

	outputFilename string
	outputRotate   bool
	rotateSize     int

	workerCount int
	fpConfig    *asn1fp.Config
}

func (c config) Init() error {
	switch c.inputFormatStr {
	case "base64":
		c.inputFormat = FormatBase64
	case "hex":
		c.inputFormat = FormatHex
	default:
		return errors.New("invalid input format " + c.inputFormatStr)
	}

	return nil
}
