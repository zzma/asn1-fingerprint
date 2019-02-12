package main

import (
	"bufio"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/pkg/profile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var log *zap.SugaredLogger

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

type Job struct {
	filepath string
}

func allocate(jobs chan Job, c *config) {
	var filepaths []string
	if isDir, err := isDirectory(c.inputPath); err != nil {
		log.Fatal("Unable to read file/directory: ", c.inputPath)
	} else if isDir {
		filepaths, err = directoryFiles(c.inputPath, c.recursiveDir)
		if err != nil {
			log.Fatal(err)
		}
	} else if !isDir {
		filepaths = []string{c.inputPath}
	}

	for _, f := range filepaths {
		log.Debugf("Allocating job: %s", f)
		jobs <- Job{filepath: f,}
	}
	close(jobs)
}

func createWorkerPool(jobs chan Job, c *config) {
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	var outputs = make(chan string)
	go outputHandler(outputs, &outputWG, c)

	var wg sync.WaitGroup

	for i := 0; i < c.workerCount; i++ {
		wg.Add(1)
		go inputHandler(jobs, outputs, &wg, c)
	}
	wg.Wait()
	close(outputs)
	outputWG.Wait()
}

func inputHandler(jobs chan Job, outputs chan string, wg *sync.WaitGroup, c *config) {
	for job := range jobs {
		log.Infof("Processing job: %s", job.filepath)
		f, err := os.Open(job.filepath)
		if err != nil {
			log.Error(err)
			continue
		}

		reader := csv.NewReader(f)
		reader.Comma = rune((c.delimiter)[0])

		records, err := reader.ReadAll()

		for _, record := range records {
			var data []byte

			line := record[c.asn1Col-1]
			switch c.inputFormat {
			case FormatHex:
				data, err = hex.DecodeString(line)
				if err != nil {
					log.Fatal(err)
				}
			case FormatBase64:
				data, err = base64.StdEncoding.DecodeString(line)
				if err != nil {
					log.Fatal(err)
				}
			default:
				log.Fatal(errors.New("invalid input format " + c.inputFormatStr))
			}

			fp, err := fingerprint(data, c)
			if err != nil {
				log.Fatal(err)
			}

			outputs <- fp
		}
	}
	wg.Done()
}

func fingerprint(bytes []byte, c *config) (string, error) {
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

func fpRecurse(tagChain []int, bytes []byte, c *config) ([]string, error) {
	var obj asn1.RawValue

	rest, err := asn1.Unmarshal(bytes, &obj)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("fpRecurse: excess data")
	}

	log.Debugf("Tags %s: %x", fpForChain(tagChain), bytes)

	fps := make([]string, 0)
	tagChain = append(tagChain, obj.Tag)

	if obj.IsCompound {
		//TODO: check for empty Sequence or Set
		elements, err := parseCompoundObj(obj.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		for _, element := range elements {
			paths, err := fpRecurse(tagChain, element.FullBytes, c)
			if err != nil {
				return nil, err
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
			if c.parseOID {
				oid, err := parseObjectIdentifier(obj.Bytes)
				if err != nil {
					return nil, err
				}
				fps = append(fps, fpForChain(tagChain)+"."+oid.String())
			} else {
				fps = append(fps, fpForChain(tagChain))
			}

		default:
			log.Errorf("invalid simple ASN1 type: %d", obj.Tag)
			return nil, errors.New("invalid ASN1 type")
		}
	}

	return fps, nil
}

func outputHandler(outputs chan string, wg *sync.WaitGroup, c *config) {
	var outputFile *os.File
	var err error

	logFileCounter := 1

	if c.outputFilename == "-" {
		outputFile = os.Stdout
	} else if len(c.outputFilename) > 0 {
		var filename string

		if c.outputRotate {
			filename = c.outputFilename + "." + strconv.Itoa(logFileCounter)
			logFileCounter += 1
		} else {
			filename = c.outputFilename
		}
		outputFile, err = os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
	}

	const WRITE_BUFFER_SIZE = 4096 * 10000
	w := bufio.NewWriterSize(outputFile, WRITE_BUFFER_SIZE)
	outputSize := 0

	for output := range outputs {
		outputSize += len(output)
		w.WriteString(output)

		if c.outputRotate && outputSize > c.rotateSize {
			w.Flush()
			outputFile.Close()

			outputFile, err = os.Create(c.outputFilename + "." + strconv.Itoa(logFileCounter))
			if err != nil {
				log.Fatal(err)
			}

			w = bufio.NewWriterSize(outputFile, WRITE_BUFFER_SIZE)

			logFileCounter += 1
			outputSize = 0
		}
	}

	w.Flush()
	outputFile.Close()
	wg.Done()

}

func main() {
	const usage = `
asn1-fingerprint: structural fingerprints of ASN.1 data

usage: %s -i <input file/directory> -o <output file>

Options:
`

	var conf config

	flag.BoolVar(&conf.profile, "profile", false, "run performance profiler")
	flag.BoolVar(&conf.verbose, "v", false, "verbose debug output")
	flag.StringVar(&conf.inputPath, "i", "", "input file/directory path")
	flag.BoolVar(&conf.recursiveDir, "r", false, "search input directory recursively")
	flag.StringVar(&conf.inputFormatStr, "format", "base64", "input data encoding format (base64, hex)")
	flag.StringVar(&conf.outputFilename, "o", "-", "output file path")
	flag.BoolVar(&conf.outputRotate, "rotate", false, "rotate output file")
	flag.IntVar(&conf.rotateSize, "rotate-size", 5000000000, "size threshold for output file rotation")
	flag.IntVar(&conf.workerCount, "workers", runtime.NumCPU(), "number of parallel parsers (one per file)")
	flag.BoolVar(&conf.parseOID, "oid", false, "parse and use OIDs in fingerprinting")
	flag.StringVar(&conf.delimiter, "d", ",", "delimiter for asn1 data")
	flag.IntVar(&conf.asn1Col, "f", 1, "column that contains asn1 data")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	if conf.profile {
		defer profile.Start().Stop()
	}

	if err := conf.Init(); err != nil {
		log.Fatal("invalid config: ", err)
	}

	if conf.verbose {
		log = initLogger(zapcore.DebugLevel)
	} else {
		log = initLogger(zapcore.InfoLevel)
	}

	jobs := make(chan Job)
	go allocate(jobs, &conf)

	createWorkerPool(jobs, &conf)
}
