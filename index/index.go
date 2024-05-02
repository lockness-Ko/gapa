package index

import (
	"slices"

	"github.com/knightsc/gapstone"
	"github.com/lockness-ko/gapa/utils"
)

type FunctionIndex struct {
}

type InstructionIndex struct {
	MnemonicKeys  []string
	MnemonicIndex map[string][]gapstone.Instruction
	MnemonicSize  int
}

func (dex *InstructionIndex) Initialise() {
	dex.MnemonicIndex = make(map[string][]gapstone.Instruction)
}

func (dex *InstructionIndex) Get(mne string) []gapstone.Instruction {
	if slices.Contains(dex.MnemonicKeys, mne) {
		return dex.MnemonicIndex[mne]
	}

	return []gapstone.Instruction{}
}

func (dex *InstructionIndex) Index(insn gapstone.Instruction) {
	dex.MnemonicSize++

	for _, mne := range dex.MnemonicKeys {
		if mne == insn.Mnemonic {
			dex.MnemonicIndex[mne] = append(dex.MnemonicIndex[mne], insn)
			return
		}
	}
	dex.MnemonicKeys = utils.Keys(dex.MnemonicIndex)
	dex.MnemonicIndex[insn.Mnemonic] = []gapstone.Instruction{insn}
}
