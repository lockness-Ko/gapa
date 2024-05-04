package main

import (
	"bytes"
	"embed"
	"flag"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/lockness-ko/gapa/gapstone"
	"github.com/lockness-ko/gapa/index"
	"github.com/lockness-ko/gapa/utils"
	elfparser "github.com/saferwall/elf"
	peparser "github.com/saferwall/pe"
	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yml
var rules_fs embed.FS

type MetaField struct {
	Name      string
	Namespace string
	Authors   []string
	Scopes    map[string]string
	Mbc       []string
	Examples  []string
}

type FileInfo struct {
	Os           string
	Imports      []string
	Exports      []string
	Sections     []string
	Arch         string
	Instructions index.InstructionIndex

	Matches []string
}

type Rule struct {
	Rule struct {
		Meta     MetaField
		Features []interface{}
	}
}

func removeDescription(name string) string {
	split := strings.Split(name, " =")

	return strings.TrimSpace(split[0])
}

func handleExport(name string, fileInfo *FileInfo) bool {
	// fileInfo.Matches = append(fileInfo.Matches, "")
	if slices.Contains(fileInfo.Exports, name) {
		return true
	}
	return false
}

func handleSection(target_sec string, fileInfo *FileInfo) bool {
	if slices.Contains(fileInfo.Sections, target_sec) {
		return true
	}
	return false
}

func handleImport(name string, fileInfo *FileInfo) bool {
	if slices.Contains(fileInfo.Imports, name) {
		return true
	}
	return false
}

func handleApi(name string, fileInfo *FileInfo) bool {
	if slices.Contains(fileInfo.Imports, name) {
		return true
	}
	return false
}

func handleOs(os string, fileInfo *FileInfo) bool {
	if os == fileInfo.Os {
		return true
	}
	return false
}

func handleArch(arch string, fileInfo *FileInfo) bool {
	if arch == fileInfo.Arch {
		return true
	}
	return false
}

func handleNumber(n interface{}, fileInfo *FileInfo) bool {
	var num uint64
	var err error
	switch n.(type) {
	case int:
		num = uint64(n.(int))
	case string:
		if len(n.(string)) > 2 {
			if n.(string)[0:2] == "0x" {
				num, err = strconv.ParseUint(n.(string)[2:], 16, 0)
			} else {
				num, err = strconv.ParseUint(n.(string), 10, 0)
			}
		} else {
			num, err = strconv.ParseUint(n.(string), 10, 0)
		}

		if err != nil {
			log.Fatalf("handleNumber %s", err)
		}
	}

	if slices.Contains(fileInfo.Instructions.NumberKeys, num) {
		return true
	}

	return false
}

func handleString(mne string, fileInfo *FileInfo) bool {
	if slices.Contains(fileInfo.Instructions.StringKeys, mne) {
		return true
	}
	return false
}

func handleMnemonic(mne string, fileInfo *FileInfo) bool {
	if slices.Contains(fileInfo.Instructions.MnemonicKeys, mne) {
		return true
	}
	return false
}

func handleOptional(fields []interface{}, fileInfo *FileInfo) bool {
	return true
}

func handleFeature(bools *[]bool, fields []interface{}, fileInfo *FileInfo) {
	for _, f := range fields {
		k := utils.Keys(f.(map[string]interface{}))[0]
		// log.Printf("handleAnd %s %s\n", k, f.(map[string]interface{}))
		nextSegment := f.(map[string]interface{})[k]

		switch k {
		case "and":
			*bools = append(*bools, handleAnd(nextSegment.([]interface{}), fileInfo))
			break
		case "or":
			*bools = append(*bools, handleOr(nextSegment.([]interface{}), fileInfo))
			break
		case "not":
			*bools = append(*bools, handleNot(nextSegment.([]interface{}), fileInfo))
			break
		case "optional":
			*bools = append(*bools, handleOptional(nextSegment.([]interface{}), fileInfo))
			break
		case "api":
			*bools = append(*bools, handleApi(nextSegment.(string), fileInfo))
			break
		case "os":
			*bools = append(*bools, handleOs(nextSegment.(string), fileInfo))
			break
		case "arch":
			*bools = append(*bools, handleArch(nextSegment.(string), fileInfo))
			break
		case "mnemonic":
			*bools = append(*bools, handleMnemonic(nextSegment.(string), fileInfo))
			break
		case "export":
			*bools = append(*bools, handleExport(nextSegment.(string), fileInfo))
			break
		case "import":
			*bools = append(*bools, handleImport(nextSegment.(string), fileInfo))
			break
		case "section":
			*bools = append(*bools, handleSection(nextSegment.(string), fileInfo))
			break
		case "string":
			*bools = append(*bools, handleString(nextSegment.(string), fileInfo))
			break
		// case "number":
		// 	switch nextSegment.(type) {
		// 	case int:
		// 		*bools = append(*bools, handleNumber(nextSegment.(int), fileInfo))
		// 	case string:
		// 		*bools = append(*bools, handleNumber(removeDescription(nextSegment.(string)), fileInfo))
		// 	}
		// 	break
		default:
			*bools = append(*bools, false)
			break
		}
	}
}

func handleAnd(fields []interface{}, fileInfo *FileInfo) bool {
	bools := []bool{}

	handleFeature(&bools, fields, fileInfo)

	// log.Printf("handleAnd %#v\n", bools)
	for _, boolean := range bools {
		if boolean == false {
			return false
		}
	}
	return true
}

func handleOr(fields []interface{}, fileInfo *FileInfo) bool {
	bools := []bool{}

	handleFeature(&bools, fields, fileInfo)

	// log.Printf("handleOr %#v\n", bools)
	for _, boolean := range bools {
		if boolean == true {
			return true
		}
	}
	return false
}

func handleNot(fields []interface{}, fileInfo *FileInfo) bool {
	bools := []bool{}

	handleFeature(&bools, fields, fileInfo)

	// log.Printf("handleOr %#v\n", bools)
	for _, boolean := range bools {
		if boolean == true {
			return false
		}
	}
	return true
}

func processCond(ops []interface{}, fileInfo *FileInfo) bool {
	bools := []bool{}

	handleFeature(&bools, ops, fileInfo)

	for _, boolean := range bools {
		if boolean == false {
			return false
		}
	}
	return true
}

func processRule(filePath string, builtinRules bool) *Rule {
	var yfile []byte
	var err error
	if builtinRules {
		yfile, err = rules_fs.ReadFile("rules/" + filePath)
	} else {
		yfile, err = os.ReadFile(filePath)
		if err != nil {
			log.Fatalf("processRule %s\n", err)
		}
	}

	r := Rule{}
	err = yaml.Unmarshal(yfile, &r)
	if err != nil {
		log.Fatal(err)
	}

	return &r
}

func disasm(data []byte, arch int) ([]gapstone.Instruction, error) {
	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		arch,
	)
	if err != nil {
		return nil, err
	}
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	insns, err := engine.Disasm(data, 0x0, 0)
	if err != nil {
		return nil, err
	}

	return insns, nil
}

func walkDir(dir []fs.DirEntry) []string {
	out := []string{}

	for _, obj := range dir {
		out = append(out, obj.Name())
	}

	return out
}

func main() {
	folderpath := flag.String("rule-folder", ".", "Path to rule folder")
	file := flag.String("file", ", please specify a file", "Path to file to analyse")
	verbose := flag.Bool("verbose", false, "")
	flag.Parse()

	rules := []Rule{}
	fileInfo := FileInfo{}

	logger := log.Default()
	logger.SetFlags(log.Lmicroseconds)

	ymlExt := ".yml"
	start := time.Now()
	logger.Println("Loading rules...")

	if *folderpath == "." {
		rules_dir, err := rules_fs.ReadDir("rules")
		if err != nil {
			log.Fatalf("rules_dir %s\n", err)
		}
		rule_paths := walkDir(rules_dir)

		for _, rule_path := range rule_paths {
			rules = append(rules, *processRule(rule_path, true))
		}
	} else {
		err := filepath.Walk(*folderpath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if len(path) < 4 {
					return nil
				}
				if path[len(path)-4:] == ymlExt {
					rules = append(rules, *processRule(path, false))
				}
				return nil
			})

		if err != nil {
			log.Println(err)
		}
	}
	dur := time.Now().Sub(start)
	logger.Printf("Loaded %d rules (%dms)\n", len(rules), dur.Milliseconds())

	dat, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("os.ReadFile %v", err)
	}

	fileInfo.Instructions.Initialise()
	logger.Println("Initialised indexes")

	start = time.Now()
	magic := dat[0:4]
	if bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		log.Println("File type: ELF")
		fileInfo.Os = "linux"

		elf, err := elfparser.New(*file)
		if err != nil {
			log.Fatalf("elfparser.New %v", err)
		}
		err = elf.Parse()
		if err != nil {
			log.Fatalf("elf.Parse %v", err)
		}
		elf_parsed := elf.F
		var capstone_arch int
		switch elf_parsed.Class() {
		case elfparser.ELFCLASS32:
			fileInfo.Arch = "i386"
			capstone_arch = gapstone.CS_MODE_32
			break
		case elfparser.ELFCLASS64:
			fileInfo.Arch = "amd64"
			capstone_arch = gapstone.CS_MODE_64
			break
		}

		for _, symbol := range elf_parsed.ELFSymbols.NamedSymbols {
			// this is pretty much wrong, more time needs to be spend on it.
			if symbol.Index == elfparser.SHN_UNDEF {
				fileInfo.Imports = append(fileInfo.Imports, symbol.Name)
			} else {
				fileInfo.Exports = append(fileInfo.Exports, symbol.Name)
			}
		}

		// for _, export := range elf_parsed.

		if capstone_arch == gapstone.CS_MODE_64 { // I don't like how the sections aren't an interface :(
			for _, sec := range elf_parsed.Sections64 {
				fileInfo.Sections = append(fileInfo.Sections, sec.SectionName)
				if sec.ELF64SectionHeader.Size <= 0 || sec.Flags&0b100 != 0b100 /* progbits */ {
					continue
				}
				d, err := sec.Data()
				if err != nil {
					continue
				}

				insns, err := disasm(d, capstone_arch)
				if err != nil {
					continue
				}

				for _, insn := range insns {
					fileInfo.Instructions.Index(insn)
				}
			}
		} else {
			for _, sec := range elf_parsed.Sections32 {
				fileInfo.Sections = append(fileInfo.Sections, sec.SectionName)
				if sec.ELF32SectionHeader.Size <= 0 || sec.Flags&0b100 != 0b100 /* progbits */ {
					continue
				}
				d, err := sec.Data()
				if err != nil {
					continue
				}

				insns, err := disasm(d, capstone_arch)
				if err != nil {
					continue
				}

				for _, insn := range insns {
					fileInfo.Instructions.Index(insn)
				}
			}
		}

	} else if bytes.Equal(magic[0:2], []byte{'M', 'Z'}) {
		log.Println("File type: PE")
		fileInfo.Os = "windows"

		pe, err := peparser.New(*file, &peparser.Options{})
		if err != nil {
			log.Fatal(err)
		}
		pe.Parse()
		var capstone_arch int

		switch pe.NtHeader.FileHeader.Machine.String() {
		case "x64":
			capstone_arch = gapstone.CS_MODE_64
			break
		case "x86":
			capstone_arch = gapstone.CS_MODE_32
			break
		}

		for _, imp := range pe.Imports {
			for _, fun := range imp.Functions {
				fileInfo.Imports = append(fileInfo.Imports, fun.Name)
			}
		}

		for _, exp := range pe.Export.Functions {
			if len(exp.Name) == 0 {
				continue
			}
			fileInfo.Exports = append(fileInfo.Exports, exp.Name)
		}

		for _, sec := range pe.Sections {
			fileInfo.Sections = append(fileInfo.Sections, sec.String())
			if sec.Header.Characteristics&0x00000020 == 0x00000020 { // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header?source=recommendations
				data := sec.Data(0, sec.Header.SizeOfRawData, pe)

				insns, err := disasm(data, capstone_arch)
				if err != nil {
					continue
				}

				for _, insn := range insns {
					fileInfo.Instructions.Index(insn)
				}
			}

		}
	} else {
		logger.Fatalln("Unrecognised file format.")
	}

	dur = time.Now().Sub(start)
	logger.Printf("Disassembled %d instructions (%dms)\n", fileInfo.Instructions.Size, dur.Milliseconds())

	// for _, mne := range fileInfo.Instructions.MnemonicKeys {
	// 	for _, inst := range fileInfo.Instructions.Get(mne) {
	// 		logger.Printf("%s %s %#v\n", inst.Mnemonic, inst.OpStr, inst.X86.Operands)
	// 	}
	// }

	// for _, rule := range rules {
	// 	start := time.Now()
	// 	res := processCond(rule.Rule.Features, fileInfo)
	// 	dur := time.Now().Sub(start)
	// 	logger.Printf("Rule \"%s\" = %t (%dms)\n", rule.Rule.Meta.Name, res, dur.Milliseconds())
	// }

	start_t := time.Now()
	var wg sync.WaitGroup
	for _, rule := range rules {
		wg.Add(1)
		go func(rule Rule, fileInfo FileInfo, verbose bool) {
			defer wg.Done()
			start := time.Now()
			res := processCond(rule.Rule.Features, &fileInfo)
			dur := time.Now().Sub(start)

			if verbose || res {
				logger.Printf("Rule \"%s\": %t (%dms)\n\t%s\n\t%s\n", rule.Rule.Meta.Name, res, dur.Milliseconds(), rule.Rule.Meta.Mbc, rule.Rule.Meta.Namespace)
			}
		}(rule, fileInfo, *verbose)
	}
	wg.Wait()
	dur_t := time.Now().Sub(start_t)
	logger.Printf("All rules took %dms\n", dur_t.Milliseconds())
}
