package index

import (
	"encoding/binary"
	"slices"

	"github.com/lockness-ko/gapa/gapstone"
	"github.com/lockness-ko/gapa/utils"
)

type FunctionIndex struct {
}

type InstructionIndex struct {
	MnemonicKeys  []string
	MnemonicIndex map[string][]*gapstone.Instruction
	NumberKeys    []uint64
	NumberIndex   map[uint64][]*gapstone.Instruction
	StringKeys    []string
	StringIndex   map[string][]*gapstone.Instruction

	Size int
}

func (dex *InstructionIndex) Initialise() {
	dex.MnemonicIndex = make(map[string][]*gapstone.Instruction)
	dex.NumberIndex = make(map[uint64][]*gapstone.Instruction)
	dex.StringIndex = make(map[string][]*gapstone.Instruction)
}

func (dex *InstructionIndex) Get(mne string) []*gapstone.Instruction {
	if slices.Contains(dex.MnemonicKeys, mne) {
		return dex.MnemonicIndex[mne]
	}

	return []*gapstone.Instruction{}
}

func (dex *InstructionIndex) Index(insn gapstone.Instruction) {
	dex.Size++

	for _, op := range insn.X86.Operands {
		if op.Type != 0x2 {
			continue
		}
		n := op.Imm

		for _, mne := range dex.NumberKeys {
			bs := make([]byte, 8)
			binary.LittleEndian.PutUint64(bs, mne)

			if mne == uint64(n) {
				dex.NumberIndex[mne] = append(dex.NumberIndex[mne], &insn)
				dex.StringIndex[string(bs)] = append(dex.StringIndex[string(bs)], &insn)
				return
			}
		}

		bs := make([]byte, 8)
		binary.LittleEndian.PutUint64(bs, uint64(n))
		dex.StringKeys = utils.Keys(dex.StringIndex)
		dex.StringIndex[string(bs)] = []*gapstone.Instruction{&insn}

		dex.NumberKeys = utils.Keys(dex.NumberIndex)
		dex.NumberIndex[uint64(n)] = []*gapstone.Instruction{&insn}
	}

	for _, mne := range dex.MnemonicKeys {
		if mne == insn.Mnemonic {
			dex.MnemonicIndex[mne] = append(dex.MnemonicIndex[mne], &insn)
			return
		}
	}
	dex.MnemonicKeys = utils.Keys(dex.MnemonicIndex)
	dex.MnemonicIndex[insn.Mnemonic] = []*gapstone.Instruction{&insn}
}
