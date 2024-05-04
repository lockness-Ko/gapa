package index

import (
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

	Size int
}

func (dex *InstructionIndex) Initialise() {
	dex.MnemonicIndex = make(map[string][]*gapstone.Instruction)
	dex.NumberIndex = make(map[uint64][]*gapstone.Instruction)
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
			if mne == uint64(n) {
				dex.NumberIndex[mne] = append(dex.NumberIndex[mne], &insn)
				return
			}
		}
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
