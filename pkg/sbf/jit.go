// Derived from solana_rbpf <https://github.com/solana-labs/rbpf>
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

package sbf

// #include <stdlib.h>
import "C"

import (
	"fmt"

	"gonum.org/v1/gonum/mathext/prng"
)

const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH = 4096
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION = 110

type OperandSize int

const (
	S0  OperandSize = 0
	S8  OperandSize = 8
	S16 OperandSize = 16
	S32 OperandSize = 32
	S64 OperandSize = 64
)

const (
	OperandSizeS0  OperandSize = S0
	OperandSizeS8  OperandSize = S8
	OperandSizeS16 OperandSize = S16
	OperandSizeS32 OperandSize = S32
	OperandSizeS64 OperandSize = S64
)

// Used to define subroutines and then call them
// See JitCompiler::set_anchor() and JitCompiler::relative_to_anchor()
const ANCHOR_EPILOGUE = 0
const ANCHOR_TRACE = 1
const ANCHOR_RUST_EXCEPTION = 2
const ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS = 3
const ANCHOR_EXCEPTION_AT = 4
const ANCHOR_CALL_DEPTH_EXCEEDED = 5
const ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT = 6
const ANCHOR_DIV_BY_ZERO = 7
const ANCHOR_DIV_OVERFLOW = 8
const ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION = 9
const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION = 10
const ANCHOR_EXIT = 11
const ANCHOR_SYSCALL = 12
const ANCHOR_BPF_CALL_PROLOGUE = 13
const ANCHOR_BPF_CALL_REG = 14
const ANCHOR_TRANSLATE_PC = 15
const ANCHOR_TRANSLATE_PC_LOOP = 16
const ANCHOR_MEMORY_ACCESS_VIOLATION = 17
const ANCHOR_TRANSLATE_MEMORY_ADDRESS = 25
const ANCHOR_COUNT = 33 // Update me when adding or removing anchors

var REGISTER_MAP = [11]uint8{
	CALLER_SAVED_REGISTERS[0],
	ARGUMENT_REGISTERS[1],
	ARGUMENT_REGISTERS[2],
	ARGUMENT_REGISTERS[3],
	ARGUMENT_REGISTERS[4],
	ARGUMENT_REGISTERS[5],
	CALLEE_SAVED_REGISTERS[2],
	CALLEE_SAVED_REGISTERS[3],
	CALLEE_SAVED_REGISTERS[4],
	CALLEE_SAVED_REGISTERS[5],
	CALLEE_SAVED_REGISTERS[1],
}

type JitCompiler struct {
	result                           *JitProgramSections
	textSectionJumps                 []Jump
	offsetInTextSection              int
	pc                               int
	lastInstructionMeterValidationPc int
	nextNoopInsertion                uint32
	programVmAddr                    uint64
	anchors                          [ANCHOR_COUNT]*uint8
	config                           *Config
	diversificationRng               *prng.Xoshiro256plusplus
	stopwatchIsActive                bool
	environmentStackKey              int32
	programArgumentKey               int32
}

type Jump struct {
	location  *uint8
	target_pc int
}

// unsafely append data to the text section
func emit(jit *JitCompiler, data interface{}) {
	size := 0

	switch val := data.(type) {
	case uint8:
		jit.result.TextSection.Uint8(val)
		size = 1
	case uint16:
		jit.result.TextSection.Uint16(val)
		size = 2
	case uint32:
		jit.result.TextSection.Uint32(val)
		size = 4
	case uint64:
		jit.result.TextSection.Uint64(val)
		size = 8
	default:
		panic(fmt.Sprintf("emit: unknown type %T", val))
	}

	jit.offsetInTextSection += int(size)
}

func emitVariableLength(jit *JitCompiler, size OperandSize, data uint64) {
	switch size {
	case S0:
	case S8:
		emit(jit, uint8(data))
	case S16:
		emit(jit, uint16(data))
	case S32:
		emit(jit, uint32(data))
	case S64:
		emit(jit, data)
	}
}
