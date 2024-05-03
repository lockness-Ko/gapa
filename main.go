package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"path/filepath"
	"sync"

	// "sync"
	"time"

	"github.com/lockness-ko/gapa/gapstone"
	"github.com/lockness-ko/gapa/index"
	"github.com/lockness-ko/gapa/utils"
	elfparser "github.com/saferwall/elf"
	peparser "github.com/saferwall/pe"
	"gopkg.in/yaml.v3"
)

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
	Instructions index.InstructionIndex
}

type Rule struct {
	Rule struct {
		Meta     MetaField
		Features []map[string]interface{}
	}
}

func handleApi(name string, fileInfo FileInfo) bool {
	for _, imp := range fileInfo.Imports {
		if name == imp {
			return true
		}
	}
	return false
}

func handleOs(os string, fileInfo FileInfo) bool {
	if os == fileInfo.Os {
		return true
	}
	return false
}

func handleOptional(fields interface{}, fileInfo FileInfo) bool {
	return false
}

func handleAnd(fields []interface{}, fileInfo FileInfo) bool {
	bools := []bool{}

	for _, f := range fields {
		k := utils.Keys(f.(map[string]interface{}))[0]
		// log.Printf("handleAnd %s %s\n", k, f.(map[string]interface{}))

		switch k {
		case "and":
			bools = append(bools, handleAnd(f.(map[string]interface{})[k].([]interface{}), fileInfo))
			break
		case "or":
			bools = append(bools, handleOr(f.(map[string]interface{})[k].([]interface{}), fileInfo))
			break
		case "api":
			bools = append(bools, handleApi(f.(map[string]interface{})[k].(string), fileInfo))
			break
		case "os":
			bools = append(bools, handleOs(f.(map[string]interface{})[k].(string), fileInfo))
			break
		default:
			bools = append(bools, false)
			break
		}
	}

	// log.Printf("handleAnd %#v\n", bools)
	if len(bools) == 0 {
		return false
	}
	for _, boolean := range bools {
		if boolean == false {
			return false
		}
	}
	return true
}

func handleOr(fields []interface{}, fileInfo FileInfo) bool {
	bools := []bool{}

	for _, f := range fields {
		k := utils.Keys(f.(map[string]interface{}))[0]
		// log.Printf("handleOr %s %s\n", k, f.(map[string]interface{}))

		switch k {
		case "and":
			bools = append(bools, handleAnd(f.(map[string]interface{})[k].([]interface{}), fileInfo))
			break
		case "or":
			bools = append(bools, handleOr(f.(map[string]interface{})[k].([]interface{}), fileInfo))
			break
		case "api":
			bools = append(bools, handleApi(f.(map[string]interface{})[k].(string), fileInfo))
			break
		case "os":
			bools = append(bools, handleOs(f.(map[string]interface{})[k].(string), fileInfo))
			break
		default:
			bools = append(bools, false)
			break
		}
	}

	// log.Printf("handleOr %#v\n", bools)
	for _, boolean := range bools {
		if boolean == true {
			return true
		}
	}
	return false
}

func processCond(ops []map[string]interface{}, fileInfo FileInfo) bool {
	for _, op := range ops {
		for _, f := range utils.Keys(op) {
			// log.Printf("%s\n", f)

			switch f {
			case "and":
				return handleAnd(op[f].([]interface{}), fileInfo)
			case "or":
				return handleOr(op[f].([]interface{}), fileInfo)
			default:
				return false
			}
		}
	}
	return false
}

func processRule(filePath string) Rule {
	yfile, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	r := Rule{}
	err = yaml.Unmarshal(yfile, &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
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

func main() {
	folderpath := flag.String("rule-folder", ".", "Path to rule folder")
	file := flag.String("file", ", please specify a file", "Path to file to analyse")
	verbose := flag.Bool("verbose", false, "")
	flag.Parse()

	rules := []Rule{}
	fileInfo := FileInfo{}

	logger := log.Default()
	logger.SetFlags(log.Lmicroseconds)

	logger.Println("Loading rules...")
	err := filepath.Walk(*folderpath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if len(path) < 4 {
				return nil
			}
			if path[len(path)-4:] == ".yml" {
				rules = append(rules, processRule(path))
			}
			return nil
		})
	logger.Printf("Loaded %d rules\n", len(rules))

	if err != nil {
		log.Println(err)
	}

	dat, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("os.ReadFile %v", err)
	}

	fileInfo.Instructions.Initialise()
	logger.Println("Initialised indexes")

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
			capstone_arch = gapstone.CS_MODE_32
			break
		case elfparser.ELFCLASS64:
			capstone_arch = gapstone.CS_MODE_64
			break
		}

		for _, symbol := range elf_parsed.ELFSymbols.NamedSymbols {
			fileInfo.Imports = append(fileInfo.Imports, symbol.Name)
		}

		if capstone_arch == gapstone.CS_MODE_64 { // I don't like how the sections aren't an interface :(
			for _, sec := range elf_parsed.Sections64 {
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

		for _, sec := range pe.Sections {
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

	logger.Printf("Disassembled %d instructions\n", fileInfo.Instructions.MnemonicSize)

	// for _, mne := range instructions.MnemonicKeys {
	// 	for _, inst := range instructions.Get(mne) {
	// 		logger.Printf("%s %s %#v\n", inst.Mnemonic, inst.OpStr, inst.X86.Operands)
	// 	}
	// }

	// for _, rule := range rules {
	// 	start := time.Now()
	// 	res := processCond(rule.Rule.Features, fileInfo)
	// 	dur := time.Now().Sub(start)
	// 	logger.Printf("Rule \"%s\" = %t (%dms)\n", rule.Rule.Meta.Name, res, dur.Milliseconds())
	// }

	var wg sync.WaitGroup
	for _, rule := range rules {
		wg.Add(1)
		go func(rule Rule, fileInfo FileInfo, verbose bool) {
			defer wg.Done()
			start := time.Now()
			res := processCond(rule.Rule.Features, fileInfo)
			dur := time.Now().Sub(start)

			if verbose || res {
				logger.Printf("Rule %s: %s = %t (%dms)\n", rule.Rule.Meta.Name, rule.Rule.Meta.Mbc, res, dur.Milliseconds())
			}
		}(rule, fileInfo, *verbose)
	}
	wg.Wait()
}
