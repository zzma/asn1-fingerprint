package main

import "errors"

type InputFormat int

const (
	FormatBase64 = InputFormat(iota)
	FormatHex
)

type config struct {
	verbose bool

	inputPath string
	inputFormatStr string
	inputFormat InputFormat
	recursiveDir bool

	outputFilename string
	outputRotate bool
	rotateSize int

	workerCount int

	parseOID bool
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
