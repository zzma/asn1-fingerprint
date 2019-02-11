package main

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var log *zap.SugaredLogger

const usage = `
asn1-fingerprint: structural fingerprints of ASN.1 data

usage: %s -i <input file/directory> -o <output file>

Options:
`

var (
	verbose        = flag.Bool("v", false, "verbose debug output")
	inputPath      = flag.String("i", "", "input file/directory path")
	recursiveDir   = flag.Bool("r", false, "search input directory recursively")
	outputFilename = flag.String("o", "asn1-fps", "output file path")
	inputFormat    = flag.String("f", "base64", "input data encoding format (base64, hex)")
)

func initLogger(logLevel zapcore.Level) *zap.SugaredLogger {
	atom := zap.NewAtomicLevelAt(logLevel)
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom), zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	defer logger.Sync()
	return logger.Sugar()
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), nil
}

func directoryFiles(directory string, recurse bool) ([]string, error) {
	filepaths := make([]string, 0)
	if recurse {
		err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				filepaths = append(filepaths, path)
			}

			return nil
		})

		if err != nil {
			return filepaths, err
		}
	} else {
		if files, err := ioutil.ReadDir(directory); err != nil {
			return filepaths, err
		} else {
			baseDir := strings.TrimSuffix(directory, "/")
			for _, info := range files {
				filepaths = append(filepaths, baseDir+"/"+info.Name())
			}
		}
	}

	return filepaths, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}

	if *verbose {
		log = initLogger(zapcore.DebugLevel)
	} else {
		log = initLogger(zapcore.InfoLevel)
	}

	var filepaths []string
	if isDir, err := isDirectory(*inputPath); err != nil {
		log.Fatal("Unable to read file/directory: ", *inputPath)
	} else if isDir {
		filepaths, err = directoryFiles(*inputPath, *recursiveDir)
		if err != nil {
			log.Fatal(err)
		}
	} else if !isDir {
		filepaths = []string{*inputPath}
	}

	
}
