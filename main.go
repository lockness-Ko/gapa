package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/knightsc/gapstone"
	"github.com/lockness-ko/gapa/index"
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

type Rule struct {
	Rule struct {
		Meta     MetaField
		Features []map[string]interface{}
	}
}

func handleAnd(fields interface{}) bool {
	return false
}

func handleOr(fields interface{}) bool {
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

func main() {
	folderpath := flag.String("rule-folder", ".", "Path to rule folder")
	file := flag.String("file", ", please specify a file", "Path to file to analyse")
	flag.Parse()

	rules := []Rule{}

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
		log.Fatal(err)
	}

	var instructions index.InstructionIndex
	instructions.Initialise()

	magic := dat[0:4]
	if bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		log.Println("File type: ELF")
		elf, err := elfparser.New(*file)
		if err != nil {
			log.Fatal(err)
		}
		err = elf.Parse()
		if err != nil {
			log.Fatal(err)
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

		engine, err := gapstone.New(
			gapstone.CS_ARCH_X86,
			capstone_arch,
		)
		if err != nil {
			log.Fatal(err)
		}
		for _, sec := range elf_parsed.Sections64 {
			if sec.ELF64SectionHeader.Size <= 0 || sec.Flags&0b100 != 0b100 /* progbits */ {
				continue
			}
			d, err := sec.Data()
			if err != nil {
				continue
			}

			insns, err := engine.Disasm(d, 0x0, 0)
			if err != nil {
				continue
			}

			for _, insn := range insns {
				instructions.Index(insn)
			}
		}

	} else if bytes.Equal(magic[0:2], []byte{'M', 'Z'}) {
		log.Println("File type: PE")
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

		engine, err := gapstone.New(
			gapstone.CS_ARCH_X86,
			capstone_arch,
		)

		for _, sec := range pe.Sections {
			if sec.Header.Characteristics&0x00000020 == 0x00000020 { // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header?source=recommendations
				data := sec.Data(0, sec.Header.SizeOfRawData, pe)

				insns, err := engine.Disasm(data, 0x0, 0)
				if err != nil {
					continue
				}

				for _, insn := range insns {
					instructions.Index(insn)
				}
			}

		}
	} else {
		logger.Fatalln("Unrecognised file format.")
	}

	logger.Printf("Disassembled %d instructions\n", instructions.MnemonicSize)

	// for _, rule := range rules {
	// fmt.Printf("%s\n", rule.Rule.Meta.Name)
	// }

	// for _, field := range r.Rule.Features {
	// 	for _, key := range Keys(field) {
	// 		fmt.Printf("%#v\n", key)
	// 		if key == "or" {
	// 			handleOr(field[key])
	// 		} else if key == "and" {
	// 			handleAnd(field[key])
	// 		}
	// 	}
	// }
}
