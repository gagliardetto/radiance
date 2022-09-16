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
	"math"
	"math/bits"
	"math/rand"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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

type Xoshiro256plusplus struct {
	o *prng.Xoshiro256plusplus
}

func (x *Xoshiro256plusplus) Seed(seed uint64) {
	x.o.Seed(seed)
}

func (x *Xoshiro256plusplus) Uint64() uint64 {
	return x.o.Uint64()
}

func (x *Xoshiro256plusplus) Int32() int32 {
	return int32(x.o.Uint64())
}

func (x *Xoshiro256plusplus) Int31() int32 {
	return int32(x.o.Uint64() >> 1)
}

func (x *Xoshiro256plusplus) Int63() int64 {
	return int64(x.Uint64() & (1<<63 - 1))
}

func (x *Xoshiro256plusplus) Uint32() uint32 {
	return uint32(x.Uint64())
}

// genrange generates a random number in the range [0, n), excluding n.
func (x *Xoshiro256plusplus) GenRange(min, max uint32) uint32 {
	// TODO: check if max is not reached
	return uint32(x.Int63())%(max-min) + min
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
	case []byte:
		jit.result.TextSection.Bytes(val)
		size = len(val)
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
	default:
		panic(fmt.Sprintf("emitVariableLength: unknown size %d", size))
	}
}

// eBPF JIT-compiled program
type JitProgram struct {
	// Holds and manages the protected memory
	sections *JitProgramSections
	// Call this with the ProgramEnvironment to execute the compiled code
	Main func(*ProgramResult, u64, *ProgramEnvironment, InstructionMeter) int64
}

func (jp JitProgram) String() string {
	return fmt.Sprintf("JitProgram %p", jp.Main)
}

// get_text_bytes
func (ex *Executable) GetTextBytes() []byte {
	panic("not implemented")
}

func (ex *Executable) GetConfig() *Config {
	panic("not implemented")
}

func (ex *Executable) GetRemaining() int {
	panic("not implemented")
}

func (ex *Executable) GetEntrypointInstructionOffset() *int64 {
	panic("not implemented")
}

func NewJitProgram(
	executable *Executable,
) (*JitProgram, error) {
	program := executable.GetTextBytes()
	jit, err := NewJitCompiler(program, executable.GetConfig())
	if err != nil {
		return nil, err
	}
	err = jit.Compile(executable)
	if err != nil {
		return nil, err
	}
	mainF := (func(*ProgramResult, u64, *ProgramEnvironment, InstructionMeter) int64)(nil) // placeholder value

	mem := jit.result.TextSection.b
	if err := SetFunctionCode(&mainF, mem); err != nil {
		_ = unix.Munmap(mem)
		return nil, err
	}

	return &JitProgram{
		sections: jit.result,
		Main:     mainF,
	}, nil
}

// Set the executable code for dstAddr. This function is entirely unsafe.
//
// dstAddr must be a pointer to a function value.
// executable must be marked with PROT_EXEC privileges through a MPROTECT system-call.
func SetFunctionCode(dstAddr interface{}, executable []byte) error {
	// See "Go 1.1 Function Calls":
	// https://docs.google.com/document/d/1bMwCey-gmqZVTpRax-ESeVuZGmjwbocYs1iHplK-cjo/pub
	type interfaceHeader struct {
		typ  uintptr
		addr **[]byte
	}
	v := reflect.ValueOf(dstAddr)
	if !v.IsValid() || v.Kind() != reflect.Ptr || v.IsNil() || !v.Elem().CanSet() || v.Elem().Kind() != reflect.Func {
		return fmt.Errorf("destination for SetFunctionCode must be a pointer to a function-value")
	}
	header := *(*interfaceHeader)(unsafe.Pointer(&dstAddr))
	*header.addr = &executable
	return nil
}

func (p *JitProgram) MemSize() int {
	return sizeOf(*p) + int(p.sections.MemSize())
}

func (p *JitProgram) MachineCodeLength() int {
	return p.sections.TextSection.Len()
}

func sizeOf(v any) int {
	return int(unsafe.Sizeof(v))
}

// This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
func emit_ins(jit *JitCompiler, instruction *X86Instruction) {
	instruction.Emit(jit)
	if jit.nextNoopInsertion == 0 {
		jit.nextNoopInsertion = uint32(jit.diversificationRng.Int63n(i64(jit.config.NoopInstructionRate * 2)))
		// X86Instruction::noop().emit(jit)?;
		emit(jit, []byte{0x90})
	} else {
		jit.nextNoopInsertion -= 1
	}
}

func emit_sanitized_load_immediate(jit *JitCompiler, size OperandSize, destination byte, value int64) {
	switch size {
	case S32:
		key := jit.diversificationRng.Int31()
		emit_ins(jit, LoadImmediate(size, destination, (value-int64(key))))
		emit_ins(jit, Alu(size, 0x81, 0, destination, i64(key), nil))
		break
	case S64:
		if destination == R11 {
			key := jit.diversificationRng.Int63()
			lowerKey := int64(int32(key))
			upperKey := int64(int32(key >> 32))
			emit_ins(jit, LoadImmediate(size, destination, i64(i64(rotate_right(u64(value-lowerKey), 32))-upperKey)))
			emit_ins(jit, Alu(size, 0x81, 0, destination, upperKey, nil))
			emit_ins(jit, Alu(size, 0xc1, 1, destination, 32, nil))
			emit_ins(jit, Alu(size, 0x81, 0, destination, lowerKey, nil))
			break
		}
		if value >= int64(math.MinInt32) && value <= int64(math.MaxInt32) {
			key := int64(jit.diversificationRng.Int31())
			emit_ins(jit, LoadImmediate(size, destination, (value-key)))
			emit_ins(jit, Alu(size, 0x81, 0, destination, key, nil))
			break
		}
		key := jit.diversificationRng.Int63()
		emit_ins(jit, LoadImmediate(size, destination, (value-key)))
		emit_ins(jit, LoadImmediate(size, R11, key))
		emit_ins(jit, Alu(size, 0x01, R11, destination, 0, nil))
		break
	default:
		panic(fmt.Sprintf("unreachable: %d", size))
	}
}

func shouldSanitizeConstant(jit *JitCompiler, value int64) bool {
	if !jit.config.SanitizeUserProvidedValues {
		return false
	}

	switch {
	case uint64(value) == 0xFFFF|
		0xFFFFFF|
		0xFFFFFFFF|
		0xFFFFFFFFFF|
		0xFFFFFFFFFFFF|
		0xFFFFFFFFFFFFFF|
		0xFFFFFFFFFFFFFFFF:
		return false
	case value <= 0xFF:
		return false
	case ^value <= 0xFF: // TODO: this corresponds to !v ???
		return false
	default:
		return true
	}
}

func emit_sanitized_alu(jit *JitCompiler, size OperandSize, opcode uint8, opcodeExtension uint8, destination uint8, immediate int64) {
	if shouldSanitizeConstant(jit, immediate) {
		emit_sanitized_load_immediate(jit, size, R11, immediate)
		emit_ins(jit, Alu(size, opcode, R11, destination, immediate, nil))
	} else {
		emit_ins(jit, Alu(size, 0x81, opcodeExtension, destination, immediate, nil))
	}
}

// Indices of slots inside the struct at initial RSP
type EnvironmentStackSlot int

const (
	// The 6 CALLEE_SAVED_REGISTERS
	LastSavedRegister EnvironmentStackSlot = 5
	// The current call depth.
	//
	// Incremented on calls and decremented on exits. It's used to enforce
	// config.max_call_depth and to know when to terminate execution.
	CallDepth EnvironmentStackSlot = 6
	// BPF frame pointer (REGISTER_MAP[FRAME_PTR_REG]).
	BpfFramePtr EnvironmentStackSlot = 7
	// The BPF stack pointer (r11). Only used when config.dynamic_stack_frames=true.
	//
	// The stack pointer isn't exposed as an actual register. Only sub and add
	// instructions (typically generated by the LLVM backend) are allowed to
	// access it. Its value is only stored in this slot and therefore the
	// register is not tracked in REGISTER_MAP.
	BpfStackPtr EnvironmentStackSlot = 8
	// Constant pointer to optional typed return value
	OptRetValPtr EnvironmentStackSlot = 9
	// Last return value of instruction_meter.get_remaining()
	PrevInsnMeter EnvironmentStackSlot = 10
	// Constant pointer to instruction_meter
	InsnMeterPtr EnvironmentStackSlot = 11
	// CPU cycles accumulated by the stop watch
	StopwatchNumerator EnvironmentStackSlot = 12
	// Number of times the stop watch was used
	StopwatchDenominator EnvironmentStackSlot = 13
	// Bumper for size_of
	SlotCount EnvironmentStackSlot = 14
)

func slotOnEnvironmentStack(jit *JitCompiler, slot EnvironmentStackSlot) int32 {
	return -8 * (int32(slot) + jit.environmentStackKey)
}

func emit_stopwatch(jit *JitCompiler, begin bool) {
	jit.stopwatchIsActive = true
	emit_ins(jit, Push(RDX, nil))
	emit_ins(jit, Push(RAX, nil))
	emit_ins(jit, Fence(FenceTypeLoad))             // lfence
	emit_ins(jit, CycleCount())                     // rdtsc
	emit_ins(jit, Fence(FenceTypeLoad))             // lfence
	emit_ins(jit, Alu(S64, 0xc1, 4, RDX, 32, nil))  // RDX <<= 32;
	emit_ins(jit, Alu(S64, 0x09, RDX, RAX, 0, nil)) // RAX |= RDX;
	if begin {
		emit_ins(jit, Alu(S64, 0x29, RAX, RBP, 0, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, StopwatchNumerator)))) // *numerator -= RAX;
	} else {
		emit_ins(jit, Alu(S64, 0x01, RAX, RBP, 0, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, StopwatchNumerator)))) // *numerator += RAX;
		emit_ins(jit, Alu(S64, 0x81, 0, RBP, 1, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, StopwatchDenominator)))) // *denominator += 1;
	}
	emit_ins(jit, Pop(RAX))
	emit_ins(jit, Pop(RDX))
}

// fn emit_validate_instruction_count(jit: &mut JitCompiler, exclusive: bool, pc: Option<usize>) {
//     if let Some(pc) = pc {
//         jit.last_instruction_meter_validation_pc = pc;
//         emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], pc as i64 + 1, None));
//     } else {
//         emit_ins(jit, X86Instruction::cmp(OperandSize::S64, R11, ARGUMENT_REGISTERS[0], None));
//     }
//     emit_ins(jit, X86Instruction::conditional_jump_immediate(if exclusive { 0x82 } else { 0x86 }, jit.relative_to_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)));
// }

func emit_validate_instruction_count(jit *JitCompiler, exclusive bool, pc *int) {
	if pc != nil {
		jit.lastInstructionMeterValidationPc = *pc
		emit_ins(jit, CmpImmediate(S64, ARGUMENT_REGISTERS[0], i64(*pc+1), nil))
	} else {
		emit_ins(jit, Cmp(S64, R11, ARGUMENT_REGISTERS[0], nil))
	}
	if exclusive {
		emit_ins(jit, ConditionalJumpImmediate(0x82, jit.relativeToAnchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)))
	} else {
		emit_ins(jit, ConditionalJumpImmediate(0x86, jit.relativeToAnchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)))
	}
}

func emit_profile_instruction_count(jit *JitCompiler, targetPc *int) {
	if targetPc != nil {
		emit_ins(jit, Alu(S64, 0x81, 0, ARGUMENT_REGISTERS[0], i64(*targetPc-jit.pc-1), nil)) // instruction_meter += target_pc - (jit.pc + 1);
	} else {
		emit_ins(jit, Alu(S64, 0x81, 5, ARGUMENT_REGISTERS[0], i64(jit.pc+1), nil)) // instruction_meter -= jit.pc + 1;
		emit_ins(jit, Alu(S64, 0x01, R11, ARGUMENT_REGISTERS[0], i64(jit.pc), nil)) // instruction_meter += target_pc;
	}
}

func emit_validate_and_profile_instruction_count(jit *JitCompiler, exclusive bool, targetPc *int) {
	if jit.config.EnableInstructionMeter {
		emit_validate_instruction_count(jit, exclusive, &jit.pc)
		emit_profile_instruction_count(jit, targetPc)
	}
}

func emit_undo_profile_instruction_count(jit *JitCompiler, targetPc int) {
	if jit.config.EnableInstructionMeter {
		emit_ins(jit, Alu(S64, 0x81, 0, ARGUMENT_REGISTERS[0], i64(jit.pc+1-targetPc), nil)) // instruction_meter += (jit.pc + 1) - target_pc;
	}
}

func emit_profile_instruction_count_finalize(jit *JitCompiler, storePcInException bool) {
	if jit.config.EnableInstructionMeter || storePcInException {
		emit_ins(jit, Alu(S64, 0x81, 0, R11, 1, nil)) // R11 += 1;
	}
	if jit.config.EnableInstructionMeter {
		emit_ins(jit, Alu(S64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, nil)) // instruction_meter -= pc + 1;
	}
	if storePcInException {
		emit_ins(jit, Load(S64, RBP, R10, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, OptRetValPtr))))
		emit_ins(jit, StoreImmediate(S64, R10, X86IndirectAccess_Offset(0), 1)) // is_err = true;
		emit_ins(jit, Alu(S64, 0x81, 0, R11, ELF_INSN_DUMP_OFFSET-1, nil))
		emit_ins(jit, Store(S64, R11, R10, X86IndirectAccess_Offset(16))) // pc = jit.pc + ebpf.ELF_INSN_DUMP_OFFSET;
	}
}

func emit_conditional_branch_reg(jit *JitCompiler, op uint8, bitwise bool, firstOperand uint8, secondOperand uint8, targetPc int) {
	emit_validate_and_profile_instruction_count(jit, false, &targetPc)
	if bitwise { // Logical
		emit_ins(jit, Test(S64, firstOperand, secondOperand, nil))
	} else { // Arithmetic
		emit_ins(jit, Cmp(S64, firstOperand, secondOperand, nil))
	}
	emit_ins(jit, LoadImmediate(S64, R11, i64(targetPc)))
	jumpOffset := jit.relativeToTargetPc(targetPc, 6)
	emit_ins(jit, ConditionalJumpImmediate(op, jumpOffset))
	emit_undo_profile_instruction_count(jit, targetPc)
}

func u8Ref(i uint8) *uint8 {
	return &i
}

func emit_conditional_branch_imm(jit *JitCompiler, op uint8, bitwise bool, immediate int64, secondOperand uint8, targetPc int) {
	emit_validate_and_profile_instruction_count(jit, false, &targetPc)
	if shouldSanitizeConstant(jit, immediate) {
		emit_sanitized_load_immediate(jit, S64, R11, immediate)
		if bitwise { // Logical
			emit_ins(jit, Test(S64, R11, secondOperand, nil))
		} else { // Arithmetic
			emit_ins(jit, Cmp(S64, R11, secondOperand, nil))
		}
	} else if bitwise { // Logical
		emit_ins(jit, TestImmediate(S64, secondOperand, immediate, nil))
	} else { // Arithmetic
		emit_ins(jit, CmpImmediate(S64, secondOperand, immediate, nil))
	}
	emit_ins(jit, LoadImmediate(S64, R11, i64(targetPc)))
	jumpOffset := jit.relativeToTargetPc(targetPc, 6)
	emit_ins(jit, ConditionalJumpImmediate(op, jumpOffset))
	emit_undo_profile_instruction_count(jit, targetPc)
}

// enum Value {
//     Register(u8),
//     RegisterIndirect(u8, i32, bool),
//     RegisterPlusConstant32(u8, i32, bool),
//     RegisterPlusConstant64(u8, i64, bool),
//     Constant64(i64, bool),
// }

type Value interface {
	isValue()
}

var (
	_ Value = &Register{0}
	_ Value = &RegisterIndirect{0, 0, false}
	_ Value = &RegisterPlusConstant32{0, 0, false}
	_ Value = &RegisterPlusConstant64{0, 0, false}
	_ Value = &Constant64{0, false}
)

type Register struct {
	register uint8
}

func (*Register) isValue() {}

type RegisterIndirect struct {
	register     uint8
	offset       int32
	userProvided bool
}

func (*RegisterIndirect) isValue() {}

type RegisterPlusConstant32 struct {
	register     uint8
	offset       int32
	userProvided bool
}

func (*RegisterPlusConstant32) isValue() {}

type RegisterPlusConstant64 struct {
	register     uint8
	constant     int64
	userProvided bool
}

func (*RegisterPlusConstant64) isValue() {}

type Constant64 struct {
	constant     int64
	userProvided bool
}

func (*Constant64) isValue() {}

func emit_bpf_call(jit *JitCompiler, dst Value) {
	// Store PC in case the bounds check fails
	emit_ins(jit, LoadImmediate(S64, R11, i64(jit.pc)))
	emit_ins(jit, CallImmediate(jit.relativeToAnchor(ANCHOR_BPF_CALL_PROLOGUE, 5)))
	switch dst := dst.(type) {
	case *Register:
		// Move vm target_address into RAX
		emit_ins(jit, Push(REGISTER_MAP[0], nil))
		if dst.register != REGISTER_MAP[0] {
			emit_ins(jit, Mov(S64, dst.register, REGISTER_MAP[0]))
		}
		emit_ins(jit, CallImmediate(jit.relativeToAnchor(ANCHOR_BPF_CALL_REG, 5)))
		emit_validate_and_profile_instruction_count(jit, false, nil)
		emit_ins(jit, Mov(S64, REGISTER_MAP[0], R11)) // Save target_pc
		emit_ins(jit, Pop(REGISTER_MAP[0]))           // Restore RAX
		emit_ins(jit, CallReg(R11, nil))              // callq *%r11
	case *Constant64:
		debug_assert(!dst.userProvided, "user provided target pc")
		emit_validate_and_profile_instruction_count(jit, false, intRef(int(dst.constant)))
		emit_ins(jit, LoadImmediate(S64, R11, dst.constant))
		jumpOffset := jit.relativeToTargetPc(int(dst.constant), 5)
		emit_ins(jit, CallImmediate(jumpOffset))
	default:
		panic("unreachable")
	}
	emit_undo_profile_instruction_count(jit, 0)
	// Restore the previous frame pointer
	emit_ins(jit, Pop(REGISTER_MAP[FRAME_PTR_REG]))
	framePtrAccess := X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, BpfFramePtr))
	emit_ins(jit, Store(S64, REGISTER_MAP[FRAME_PTR_REG], RBP, framePtrAccess))
	// TODO: go has only one iterator; test this.
	for i := len(REGISTER_MAP) - 1; i >= FIRST_SCRATCH_REG; i-- {
		// take only first SCRATCH_REGS
		if i-FIRST_SCRATCH_REG >= SCRATCH_REGS {
			break
		}
		emit_ins(jit, Pop(REGISTER_MAP[i]))
	}
}

func intRef(i int) *int {
	return &i
}

type Argument struct {
	index int
	value Value
}

type ByteSlice []byte

// Iter
func (s ByteSlice) Iter() *ByteSliceIter {
	return &ByteSliceIter{s, 0}
}

type ByteSliceIter struct {
	slice ByteSlice
	index int
}

// Reverses an iterator's direction.
// Usually, iterators iterate from left to right. After using rev(), an iterator will instead iterate from right to left
func (i *ByteSliceIter) Rev() (byte, bool) {
	if i.index >= len(i.slice) {
		return 0, false
	}
	i.index++
	return i.slice[len(i.slice)-i.index], true
}

func (i *ByteSliceIter) Next() (byte, bool) {
	if i.index >= len(i.slice) {
		return 0, false
	}
	value := i.slice[i.index]
	i.index++
	return value, true
}

func (i *ByteSliceIter) Position(callback func(byte) bool) *int {
	for index, value := range i.slice[i.index:] {
		if callback(value) {
			return &index
		}
	}
	return nil
}

func emit_rust_call(jit *JitCompiler, dst Value, arguments []Argument, result_reg *uint8, check_exception bool) {
	saved_registers := CALLER_SAVED_REGISTERS[:]
	if result_reg != nil {
		dst := ByteSlice(saved_registers).Iter().Position(func(x uint8) bool { return x == *result_reg })
		debug_assert(dst != nil, "")
		if dst != nil {
			saved_registers = append(saved_registers[:*dst], saved_registers[*dst+1:]...)
		}
	}

	// Save registers on stack
	for _, reg := range saved_registers {
		emit_ins(jit, Push(reg, nil))
	}

	// Pass arguments
	stack_arguments := 0
	for _, argument := range arguments {
		is_stack_argument := argument.index >= len(ARGUMENT_REGISTERS)
		var dst uint8
		if is_stack_argument {
			stack_arguments++
			dst = R11
		} else {
			dst = ARGUMENT_REGISTERS[argument.index]
		}
		switch val := argument.value.(type) {
		case *Register:
			if is_stack_argument {
				emit_ins(jit, Push(val.register, nil))
			} else if val.register != dst {
				emit_ins(jit, Mov(OperandSizeS64, val.register, dst))
			}
		case *RegisterIndirect:
			debug_assert(!val.userProvided, "")
			if is_stack_argument {
				emit_ins(jit, Push(val.register, X86IndirectAccess_Offset(val.offset)))
			} else {
				emit_ins(jit, Load(OperandSizeS64, val.register, dst, X86IndirectAccess_Offset(val.offset)))
			}
		case *RegisterPlusConstant32:
			debug_assert(!val.userProvided, "")
			if is_stack_argument {
				emit_ins(jit, Push(val.register, nil))
				emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, int64(val.offset), X86IndirectAccess_OffsetIndexShift{0, RSP, 0}))
			} else {
				emit_ins(jit, Lea(OperandSizeS64, val.register, dst, X86IndirectAccess_Offset(val.offset)))
			}
		case *RegisterPlusConstant64:
			debug_assert(!val.userProvided, "")
			if is_stack_argument {
				emit_ins(jit, Push(val.register, nil))
				emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, val.constant, X86IndirectAccess_OffsetIndexShift{0, RSP, 0}))
			} else {
				emit_ins(jit, LoadImmediate(OperandSizeS64, dst, val.constant))
				emit_ins(jit, Alu(OperandSizeS64, 0x01, val.register, dst, 0, nil))
			}
		case *Constant64:
			debug_assert(!val.userProvided, "")
			emit_ins(jit, LoadImmediate(OperandSizeS64, dst, val.constant))
		}
	}

	switch val := dst.(type) {
	case *Register:
		emit_ins(jit, CallReg(val.register, nil))
	case *Constant64:
		debug_assert(!val.userProvided, "")
		emit_ins(jit, LoadImmediate(OperandSizeS64, RAX, val.constant))
		emit_ins(jit, CallReg(RAX, nil))
	default:
		panic("unreachable")
	}

	// Save returned value in result register
	if result_reg != nil {
		emit_ins(jit, Mov(OperandSizeS64, RAX, *result_reg))
	}

	// Restore registers from stack
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, int64(stack_arguments*8), nil))
	// iterate in reverse order on saved_registers
	for i := len(saved_registers) - 1; i >= 0; i-- {
		emit_ins(jit, Pop(saved_registers[i]))
	}

	if check_exception {
		// Test if result indicates that an error occured
		emit_ins(jit, Load(OperandSizeS64, RBP, R11, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, OptRetValPtr))))
		emit_ins(jit, CmpImmediate(OperandSizeS64, R11, 0, X86IndirectAccess_Offset(0)))
	}
}

func emit_address_translation(jit *JitCompiler, host_addr uint8, vm_addr Value, len uint64, access_type AccessType) {
	switch val := vm_addr.(type) {
	case *RegisterPlusConstant64:
		if val.userProvided && shouldSanitizeConstant(jit, val.constant) {
			emit_sanitized_load_immediate(jit, OperandSizeS64, R11, val.constant)
		} else {
			emit_ins(jit, LoadImmediate(OperandSizeS64, R11, val.constant))
		}
		emit_ins(jit, Alu(OperandSizeS64, 0x01, val.register, R11, 0, nil))
	case *Constant64:
		if val.userProvided && shouldSanitizeConstant(jit, val.constant) {
			emit_sanitized_load_immediate(jit, OperandSizeS64, R11, val.constant)
		} else {
			emit_ins(jit, LoadImmediate(OperandSizeS64, R11, val.constant))
		}
	default:
		panic("unreachable")
	}
	anchor := ANCHOR_TRANSLATE_MEMORY_ADDRESS + u64_(len).trailing_zeros() + 4*uint64(access_type)
	emit_ins(jit, CallImmediate(jit.relativeToAnchor(uint(anchor), 5)))
	emit_ins(jit, Mov(OperandSizeS64, R11, host_addr))
}

func emit_shift(jit *JitCompiler, size OperandSize, opcode_extension uint8, source uint8, destination uint8, immediate *int64) {
	if immediate != nil {
		if shouldSanitizeConstant(jit, *immediate) {
			emit_sanitized_load_immediate(jit, OperandSizeS32, source, *immediate)
		} else {
			emit_ins(jit, Alu(size, 0xc1, opcode_extension, destination, *immediate, nil))
			return
		}
	}
	if size == OperandSizeS32 {
		emit_ins(jit, Alu(OperandSizeS32, 0x81, 4, destination, -1, nil)) // Mask to 32 bit
	}
	if source == RCX {
		if destination == RCX {
			emit_ins(jit, Alu(size, 0xd3, opcode_extension, destination, 0, nil))
		} else {
			emit_ins(jit, Push(RCX, nil))
			emit_ins(jit, Alu(size, 0xd3, opcode_extension, destination, 0, nil))
			emit_ins(jit, Pop(RCX))
		}
	} else if destination == RCX {
		if source != R11 {
			emit_ins(jit, Push(source, nil))
		}
		emit_ins(jit, Xchg(OperandSizeS64, source, RCX, nil))
		emit_ins(jit, Alu(size, 0xd3, opcode_extension, source, 0, nil))
		emit_ins(jit, Mov(OperandSizeS64, source, RCX))
		if source != R11 {
			emit_ins(jit, Pop(source))
		}
	} else {
		emit_ins(jit, Push(RCX, nil))
		emit_ins(jit, Mov(OperandSizeS64, source, RCX))
		emit_ins(jit, Alu(size, 0xd3, opcode_extension, destination, 0, nil))
		emit_ins(jit, Pop(RCX))
	}
}

func emit_muldivmod(jit *JitCompiler, opc uint8, src uint8, dst uint8, imm *int64) {
	mul := (opc & BPF_ALU_OP_MASK) == (MUL32_IMM & BPF_ALU_OP_MASK)
	div := (opc & BPF_ALU_OP_MASK) == (DIV32_IMM & BPF_ALU_OP_MASK)
	sdiv := (opc & BPF_ALU_OP_MASK) == (SDIV32_IMM & BPF_ALU_OP_MASK)
	modrm := (opc & BPF_ALU_OP_MASK) == (MOD32_IMM & BPF_ALU_OP_MASK)
	size := OperandSizeS32
	if (opc & BPF_CLS_MASK) == BPF_ALU64 {
		size = OperandSizeS64
	}

	if !mul && imm == nil {
		// Save pc
		emit_ins(jit, LoadImmediate(OperandSizeS64, R11, i64(jit.pc)))
		emit_ins(jit, Test(size, src, src, nil)) // src == 0
		emit_ins(jit, ConditionalJumpImmediate(0x84, jit.relativeToAnchor(ANCHOR_DIV_BY_ZERO, 6)))
	}

	// sdiv overflows with MIN / -1. If we have an immediate and it's not -1, we
	// don't need any checks.
	if sdiv && imm == nil || *imm == -1 {
		if size == OperandSizeS64 {
			emit_ins(jit, LoadImmediate(size, R11, i64(math.MinInt64)))
		} else {
			emit_ins(jit, LoadImmediate(size, R11, i64(math.MinInt32)))
		}
		emit_ins(jit, Cmp(size, dst, R11, nil)) // dst == MIN

		if imm == nil {
			// The exception case is: dst == MIN && src == -1
			// Via De Morgan's law becomes: !(dst != MIN || src != -1)
			// Also, we know that src != 0 in here, so we can use it to set R11 to something not zero
			emit_ins(jit, LoadImmediate(size, R11, 0))      // No XOR here because we need to keep the status flags
			emit_ins(jit, Cmov(size, 0x45, src, R11))       // if dst != MIN { r11 = src; }
			emit_ins(jit, CmpImmediate(size, src, -1, nil)) // src == -1
			emit_ins(jit, Cmov(size, 0x45, src, R11))       // if src != -1 { r11 = src; }
			emit_ins(jit, Test(size, R11, R11, nil))        // r11 == 0
		}

		// MIN / -1, raise EbpfError::DivideOverflow(pc)
		emit_ins(jit, LoadImmediate(OperandSizeS64, R11, i64(jit.pc)))
		emit_ins(jit, ConditionalJumpImmediate(0x84, jit.relativeToAnchor(ANCHOR_DIV_OVERFLOW, 6)))
	}

	if dst != RAX {
		emit_ins(jit, Push(RAX, nil))
	}
	if dst != RDX {
		emit_ins(jit, Push(RDX, nil))
	}

	if imm != nil {
		if shouldSanitizeConstant(jit, *imm) {
			emit_sanitized_load_immediate(jit, OperandSizeS64, R11, *imm)
		} else {
			emit_ins(jit, LoadImmediate(OperandSizeS64, R11, *imm))
		}
	} else {
		emit_ins(jit, Mov(OperandSizeS64, src, R11))
	}

	if dst != RAX {
		emit_ins(jit, Mov(OperandSizeS64, dst, RAX))
	}

	if div || modrm {
		emit_ins(jit, Alu(size, 0x31, RDX, RDX, 0, nil)) // RDX = 0
	} else if sdiv {
		emit_ins(jit, DividendSignExtension(size)) // (RAX, RDX) = RAX as i128
	}

	if mul {
		emit_ins(jit, Alu(size, 0xf7, 4, R11, 0, nil))
	} else if sdiv {
		emit_ins(jit, Alu(size, 0xf7, 7, R11, 0, nil))
	} else {
		emit_ins(jit, Alu(size, 0xf7, 6, R11, 0, nil))
	}

	if dst != RDX {
		if modrm {
			emit_ins(jit, Mov(OperandSizeS64, RDX, dst))
		}
		emit_ins(jit, Pop(RDX))
	}
	if dst != RAX {
		if !modrm {
			emit_ins(jit, Mov(OperandSizeS64, RAX, dst))
		}
		emit_ins(jit, Pop(RAX))
	}

	if size == OperandSizeS32 {
		if mul || sdiv {
			emit_ins(jit, Alu(OperandSizeS64, 0x63, dst, dst, 0, nil)) // sign extend i32 to i64
		}
	}
}

//	fn emit_set_exception_kind<E: UserDefinedError>(jit: &mut JitCompiler, err: EbpfError<E>) {
//	    let err = Result::<u64, EbpfError<E>>::Err(err);
//	    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
//	    emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::OptRetValPtr))));
//	    emit_ins(jit, X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(8), err_kind as i64));
//	}
func emit_set_exception_kind(jit *JitCompiler, err EbpfError) {
	// TODO: what is this?
	emit_ins(jit, Load(OperandSizeS64, RBP, R10, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, OptRetValPtr))))
	emit_ins(jit, StoreImmediate(OperandSizeS64, R10, X86IndirectAccess_Offset(8), int64(err.ErrorKindIndex())))
}

type JitJump struct {
	location  unsafe.Pointer
	target_pc int
}

type JitCompiler struct {
	result                           *JitProgramSections
	textSectionJumps                 []*JitJump
	offsetInTextSection              int
	pc                               int
	lastInstructionMeterValidationPc int
	nextNoopInsertion                uint32
	programVmAddr                    uint64
	anchors                          [ANCHOR_COUNT]unsafe.Pointer
	config                           *Config
	diversificationRng               *rand.Rand
	stopwatchIsActive                bool
	environmentStackKey              int32
	programArgumentKey               int32
}

func (jc *JitCompiler) index(_index int) *uint8 {
	return &jc.result.TextSection.Get()[_index]
}

func (c *JitCompiler) String() string {
	s := fmt.Sprintf("JIT text_section: [")
	for _, i := range c.result.TextSection.Get() {
		s += fmt.Sprintf(" %v,", i)
	}
	s += fmt.Sprintf(" ] | ")
	s += fmt.Sprintf(
		"JIT state: memory: %p, pc: %v, offset_in_text_section: %v, pc_section: %v, anchors: %v, text_section_jumps: %v",
		c.result.PcSection,
		c.pc,
		c.offsetInTextSection,
		c.result.PcSection.Get(),
		c.anchors,
		c.textSectionJumps,
	)
	return s
}

// Compile the program into machine code
func (jit JitCompiler) Compile(executable *Executable) error {
	panic("not implemented")
}

func NewJitCompiler(
	program []byte,
	config *Config,
) (*JitCompiler, error) {
	// if we are on windows, we can't JIT
	if runtime.GOOS == "windows" {
		panic("JIT not supported on windows")
	}

	// if we are not on x86_64, we can't JIT
	if runtime.GOARCH != "amd64" {
		panic("JIT is only supported on x86_64")
	}

	// Scan through program to find actual number of instructions
	pc := 0
	for (pc+1)*INSN_SIZE <= len(program) {
		insn := GetInsnUnchecked(program, u64(pc))
		switch insn.Opc {
		case LD_DW_IMM:
			pc += 2
		default:
			pc += 1
		}
	}

	codeLengthEstimate := u64(MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION*pc)
	if config.NoopInstructionRate != 0 {
		codeLengthEstimate += codeLengthEstimate / config.NoopInstructionRate
	}
	result, err := NewJitProgramSections(pc+1, codeLengthEstimate)
	if err != nil {
		return nil, err
	}

	diversificationRng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var environmentStackKey, programArgumentKey int32
	if config.EncryptEnvironmentRegisters {
		environmentStackKey = diversificationRng.Int31() / 16 // -3 bits for 8 Byte alignment, and -1 bit to have encoding space for EnvironmentStackSlot::SlotCount
		programArgumentKey = diversificationRng.Int31() / 2   // -1 bit to have encoding space for (ProgramEnvironment::SYSCALLS_OFFSET + syscall.context_object_slot) * 8
	} else {
		environmentStackKey = 0
		programArgumentKey = 0
	}

	nextNoopInsertion := uint32(math.MaxUint32)
	if config.NoopInstructionRate != 0 {
		nextNoopInsertion = uint32(diversificationRng.Intn(int(config.NoopInstructionRate * 2)))
	}

	return &JitCompiler{
		result:                           result,
		textSectionJumps:                 make([]*JitJump, 0),
		offsetInTextSection:              0,
		pc:                               0,
		lastInstructionMeterValidationPc: 0,
		nextNoopInsertion:                nextNoopInsertion,
		programVmAddr:                    0,
		anchors:                          [ANCHOR_COUNT]unsafe.Pointer{}, // TODO: is this an array of pointers?
		config:                           config,
		diversificationRng:               diversificationRng,
		stopwatchIsActive:                false,
		environmentStackKey:              environmentStackKey,
		programArgumentKey:               programArgumentKey,
	}, nil
}

//     fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
//             executable: &Pin<Box<Executable<E, I>>>) -> Result<(), EbpfError<E>> {
//         let text_section_base = self.result.text_section.as_ptr();
//         let (program_vm_addr, program) = executable.get_text_bytes();
//         self.program_vm_addr = program_vm_addr;

//         self.generate_prologue::<E, I>(executable)?;

//         // Have these in front so that the linear search of ANCHOR_TRANSLATE_PC does not terminate early
//         self.generate_subroutines::<E, I>()?;

//         while self.pc * ebpf::INSN_SIZE < program.len() {
//             if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
//                 return Err(EbpfError::ExhaustedTextSegment(self.pc));
//             }
//             let mut insn = ebpf::get_insn_unchecked(program, self.pc);
//             self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;

//             // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
//             if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
//                 emit_validate_instruction_count(self, true, Some(self.pc));
//             }

//             if self.config.enable_instruction_tracing {
//                 emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
//                 emit_ins(self, X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_TRACE, 5)));
//                 emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, 0));
//             }

//             let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };
//             let src = REGISTER_MAP[insn.src as usize];
//             let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

//             match insn.opc {
//                 _ if insn.dst == STACK_PTR_REG as u8 && self.config.dynamic_stack_frames => {
//                     let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
//                     match insn.opc {
//                         ebpf::SUB64_IMM => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 5, RBP, insn.imm, Some(stack_ptr_access))),
//                         ebpf::ADD64_IMM => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, insn.imm, Some(stack_ptr_access))),
//                         _ => {
//                             #[cfg(debug_assertions)]
//                             unreachable!("unexpected insn on r11")
//                         }
//                     }
//                 }

//                 ebpf::LD_DW_IMM  => {
//                     emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
//                     self.pc += 1;
//                     self.result.pc_section[self.pc] = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
//                     ebpf::augment_lddw_unchecked(program, &mut insn);
//                     if should_sanitize_constant(self, insn.imm) {
//                         emit_sanitized_load_immediate(self, OperandSize::S64, dst, insn.imm);
//                     } else {
//                         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
//                     }
//                 },

//                 // BPF_LDX class
//                 ebpf::LD_B_REG   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, AccessType::Load);
//                     emit_ins(self, X86Instruction::load(OperandSize::S8, R11, dst, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::LD_H_REG   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, AccessType::Load);
//                     emit_ins(self, X86Instruction::load(OperandSize::S16, R11, dst, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::LD_W_REG   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, AccessType::Load);
//                     emit_ins(self, X86Instruction::load(OperandSize::S32, R11, dst, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::LD_DW_REG  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, AccessType::Load);
//                     emit_ins(self, X86Instruction::load(OperandSize::S64, R11, dst, X86IndirectAccess::Offset(0)));
//                 },

//                 // BPF_ST class
//                 ebpf::ST_B_IMM   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store);
//                     emit_ins(self, X86Instruction::store_immediate(OperandSize::S8, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
//                 },
//                 ebpf::ST_H_IMM   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store);
//                     emit_ins(self, X86Instruction::store_immediate(OperandSize::S16, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
//                 },
//                 ebpf::ST_W_IMM   => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store);
//                     emit_ins(self, X86Instruction::store_immediate(OperandSize::S32, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
//                 },
//                 ebpf::ST_DW_IMM  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store);
//                     emit_ins(self, X86Instruction::store_immediate(OperandSize::S64, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
//                 },

//                 // BPF_STX class
//                 ebpf::ST_B_REG  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store);
//                     emit_ins(self, X86Instruction::store(OperandSize::S8, src, R11, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::ST_H_REG  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store);
//                     emit_ins(self, X86Instruction::store(OperandSize::S16, src, R11, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::ST_W_REG  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store);
//                     emit_ins(self, X86Instruction::store(OperandSize::S32, src, R11, X86IndirectAccess::Offset(0)));
//                 },
//                 ebpf::ST_DW_REG  => {
//                     emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store);
//                     emit_ins(self, X86Instruction::store(OperandSize::S64, src, R11, X86IndirectAccess::Offset(0)));
//                 },

//                 // BPF_ALU class
//                 ebpf::ADD32_IMM  => {
//                     emit_sanitized_alu(self, OperandSize::S32, 0x01, 0, dst, insn.imm);
//                     emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
//                 },
//                 ebpf::ADD32_REG  => {
//                     emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x01, src, dst, 0, None));
//                     emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
//                 },
//                 ebpf::SUB32_IMM  => {
//                     emit_sanitized_alu(self, OperandSize::S32, 0x29, 5, dst, insn.imm);
//                     emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
//                 },
//                 ebpf::SUB32_REG  => {
//                     emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x29, src, dst, 0, None));
//                     emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
//                 },
//                 ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::SDIV32_IMM | ebpf::MOD32_IMM  =>
//                     emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm)),
//                 ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::SDIV32_REG | ebpf::MOD32_REG  =>
//                     emit_muldivmod(self, insn.opc, src, dst, None),
//                 ebpf::OR32_IMM   => emit_sanitized_alu(self, OperandSize::S32, 0x09, 1, dst, insn.imm),
//                 ebpf::OR32_REG   => emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x09, src, dst, 0, None)),
//                 ebpf::AND32_IMM  => emit_sanitized_alu(self, OperandSize::S32, 0x21, 4, dst, insn.imm),
//                 ebpf::AND32_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x21, src, dst, 0, None)),
//                 ebpf::LSH32_IMM  => emit_shift(self, OperandSize::S32, 4, R11, dst, Some(insn.imm)),
//                 ebpf::LSH32_REG  => emit_shift(self, OperandSize::S32, 4, src, dst, None),
//                 ebpf::RSH32_IMM  => emit_shift(self, OperandSize::S32, 5, R11, dst, Some(insn.imm)),
//                 ebpf::RSH32_REG  => emit_shift(self, OperandSize::S32, 5, src, dst, None),
//                 ebpf::NEG32      => emit_ins(self, X86Instruction::alu(OperandSize::S32, 0xf7, 3, dst, 0, None)),
//                 ebpf::XOR32_IMM  => emit_sanitized_alu(self, OperandSize::S32, 0x31, 6, dst, insn.imm),
//                 ebpf::XOR32_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x31, src, dst, 0, None)),
//                 ebpf::MOV32_IMM  => {
//                     if should_sanitize_constant(self, insn.imm) {
//                         emit_sanitized_load_immediate(self, OperandSize::S32, dst, insn.imm);
//                     } else {
//                         emit_ins(self, X86Instruction::load_immediate(OperandSize::S32, dst, insn.imm));
//                     }
//                 }
//                 ebpf::MOV32_REG  => emit_ins(self, X86Instruction::mov(OperandSize::S32, src, dst)),
//                 ebpf::ARSH32_IMM => emit_shift(self, OperandSize::S32, 7, R11, dst, Some(insn.imm)),
//                 ebpf::ARSH32_REG => emit_shift(self, OperandSize::S32, 7, src, dst, None),
//                 ebpf::LE         => {
//                     match insn.imm {
//                         16 => {
//                             emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
//                         }
//                         32 => {
//                             emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, -1, None)); // Mask to 32 bit
//                         }
//                         64 => {}
//                         _ => {
//                             return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
//                         }
//                     }
//                 },
//                 ebpf::BE         => {
//                     match insn.imm {
//                         16 => {
//                             emit_ins(self, X86Instruction::bswap(OperandSize::S16, dst));
//                             emit_ins(self, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
//                         }
//                         32 => emit_ins(self, X86Instruction::bswap(OperandSize::S32, dst)),
//                         64 => emit_ins(self, X86Instruction::bswap(OperandSize::S64, dst)),
//                         _ => {
//                             return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
//                         }
//                     }
//                 },

//                 // BPF_ALU64 class
//                 ebpf::ADD64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x01, 0, dst, insn.imm),
//                 ebpf::ADD64_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x01, src, dst, 0, None)),
//                 ebpf::SUB64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x29, 5, dst, insn.imm),
//                 ebpf::SUB64_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x29, src, dst, 0, None)),
//                 ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::SDIV64_IMM | ebpf::MOD64_IMM  =>
//                     emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm)),
//                 ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::SDIV64_REG | ebpf::MOD64_REG  =>
//                     emit_muldivmod(self, insn.opc, src, dst, None),
//                 ebpf::OR64_IMM   => emit_sanitized_alu(self, OperandSize::S64, 0x09, 1, dst, insn.imm),
//                 ebpf::OR64_REG   => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x09, src, dst, 0, None)),
//                 ebpf::AND64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x21, 4, dst, insn.imm),
//                 ebpf::AND64_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x21, src, dst, 0, None)),
//                 ebpf::LSH64_IMM  => emit_shift(self, OperandSize::S64, 4, R11, dst, Some(insn.imm)),
//                 ebpf::LSH64_REG  => emit_shift(self, OperandSize::S64, 4, src, dst, None),
//                 ebpf::RSH64_IMM  => emit_shift(self, OperandSize::S64, 5, R11, dst, Some(insn.imm)),
//                 ebpf::RSH64_REG  => emit_shift(self, OperandSize::S64, 5, src, dst, None),
//                 ebpf::NEG64      => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xf7, 3, dst, 0, None)),
//                 ebpf::XOR64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x31, 6, dst, insn.imm),
//                 ebpf::XOR64_REG  => emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x31, src, dst, 0, None)),
//                 ebpf::MOV64_IMM  => {
//                     if should_sanitize_constant(self, insn.imm) {
//                         emit_sanitized_load_immediate(self, OperandSize::S64, dst, insn.imm);
//                     } else {
//                         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
//                     }
//                 }
//                 ebpf::MOV64_REG  => emit_ins(self, X86Instruction::mov(OperandSize::S64, src, dst)),
//                 ebpf::ARSH64_IMM => emit_shift(self, OperandSize::S64, 7, R11, dst, Some(insn.imm)),
//                 ebpf::ARSH64_REG => emit_shift(self, OperandSize::S64, 7, src, dst, None),

//                 // BPF_JMP class
//                 ebpf::JA         => {
//                     emit_validate_and_profile_instruction_count(self, false, Some(target_pc));
//                     emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
//                     let jump_offset = self.relative_to_target_pc(target_pc, 5);
//                     emit_ins(self, X86Instruction::jump_immediate(jump_offset));
//                 },
//                 ebpf::JEQ_IMM    => emit_conditional_branch_imm(self, 0x84, false, insn.imm, dst, target_pc),
//                 ebpf::JEQ_REG    => emit_conditional_branch_reg(self, 0x84, false, src, dst, target_pc),
//                 ebpf::JGT_IMM    => emit_conditional_branch_imm(self, 0x87, false, insn.imm, dst, target_pc),
//                 ebpf::JGT_REG    => emit_conditional_branch_reg(self, 0x87, false, src, dst, target_pc),
//                 ebpf::JGE_IMM    => emit_conditional_branch_imm(self, 0x83, false, insn.imm, dst, target_pc),
//                 ebpf::JGE_REG    => emit_conditional_branch_reg(self, 0x83, false, src, dst, target_pc),
//                 ebpf::JLT_IMM    => emit_conditional_branch_imm(self, 0x82, false, insn.imm, dst, target_pc),
//                 ebpf::JLT_REG    => emit_conditional_branch_reg(self, 0x82, false, src, dst, target_pc),
//                 ebpf::JLE_IMM    => emit_conditional_branch_imm(self, 0x86, false, insn.imm, dst, target_pc),
//                 ebpf::JLE_REG    => emit_conditional_branch_reg(self, 0x86, false, src, dst, target_pc),
//                 ebpf::JSET_IMM   => emit_conditional_branch_imm(self, 0x85, true, insn.imm, dst, target_pc),
//                 ebpf::JSET_REG   => emit_conditional_branch_reg(self, 0x85, true, src, dst, target_pc),
//                 ebpf::JNE_IMM    => emit_conditional_branch_imm(self, 0x85, false, insn.imm, dst, target_pc),
//                 ebpf::JNE_REG    => emit_conditional_branch_reg(self, 0x85, false, src, dst, target_pc),
//                 ebpf::JSGT_IMM   => emit_conditional_branch_imm(self, 0x8f, false, insn.imm, dst, target_pc),
//                 ebpf::JSGT_REG   => emit_conditional_branch_reg(self, 0x8f, false, src, dst, target_pc),
//                 ebpf::JSGE_IMM   => emit_conditional_branch_imm(self, 0x8d, false, insn.imm, dst, target_pc),
//                 ebpf::JSGE_REG   => emit_conditional_branch_reg(self, 0x8d, false, src, dst, target_pc),
//                 ebpf::JSLT_IMM   => emit_conditional_branch_imm(self, 0x8c, false, insn.imm, dst, target_pc),
//                 ebpf::JSLT_REG   => emit_conditional_branch_reg(self, 0x8c, false, src, dst, target_pc),
//                 ebpf::JSLE_IMM   => emit_conditional_branch_imm(self, 0x8e, false, insn.imm, dst, target_pc),
//                 ebpf::JSLE_REG   => emit_conditional_branch_reg(self, 0x8e, false, src, dst, target_pc),
//                 ebpf::CALL_IMM   => {
//                     // For JIT, syscalls MUST be registered at compile time. They can be
//                     // updated later, but not created after compiling (we need the address of the
//                     // syscall function in the JIT-compiled program).

//                     let mut resolved = false;
//                     let (syscalls, calls) = if self.config.static_syscalls {
//                         (insn.src == 0, insn.src != 0)
//                     } else {
//                         (true, true)
//                     };

//                     if syscalls {
//                         if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
//                             if self.config.enable_instruction_meter {
//                                 emit_validate_and_profile_instruction_count(self, true, Some(0));
//                             }
//                             emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, syscall.function as *const u8 as i64));
//                             emit_ins(self, X86Instruction::load(OperandSize::S64, R10, RAX, X86IndirectAccess::Offset(ProgramEnvironment::SYSCALLS_OFFSET as i32 + syscall.context_object_slot as i32 * 8 + self.program_argument_key)));
//                             emit_ins(self, X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_SYSCALL, 5)));
//                             if self.config.enable_instruction_meter {
//                                 emit_undo_profile_instruction_count(self, 0);
//                             }
//                             // Throw error if the result indicates one
//                             emit_ins(self, X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))));
//                             emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
//                             emit_ins(self, X86Instruction::conditional_jump_immediate(0x85, self.relative_to_anchor(ANCHOR_RUST_EXCEPTION, 6)));

//                             resolved = true;
//                         }
//                     }

//                     if calls {
//                         if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
//                             emit_bpf_call(self, Value::Constant64(target_pc as i64, false));
//                             resolved = true;
//                         }
//                     }

//                     if !resolved {
//                         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
//                         emit_ins(self, X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 5)));
//                     }
//                 },
//                 ebpf::CALL_REG  => {
//                     emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]));
//                 },
//                 ebpf::EXIT      => {
//                     let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
//                     emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));

//                     // If CallDepth == 0, we've reached the exit instruction of the entry point
//                     emit_ins(self, X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], 0, None));
//                     if self.config.enable_instruction_meter {
//                         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
//                     }
//                     // we're done
//                     emit_ins(self, X86Instruction::conditional_jump_immediate(0x84, self.relative_to_anchor(ANCHOR_EXIT, 6)));

//                     // else decrement and update CallDepth
//                     emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 5, REGISTER_MAP[FRAME_PTR_REG], 1, None));
//                     emit_ins(self, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, call_depth_access));

//                     // and return
//                     emit_validate_and_profile_instruction_count(self, false, Some(0));
//                     emit_ins(self, X86Instruction::return_near());
//                 },

//                 _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
//             }

//             self.pc += 1;
//         }
//         // Bumper so that the linear search of ANCHOR_TRANSLATE_PC can not run off
//         self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;

//         // Bumper in case there was no final exit
//         if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
//             return Err(EbpfError::ExhaustedTextSegment(self.pc));
//         }
//         emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
//         emit_set_exception_kind::<E>(self, EbpfError::ExecutionOverrun(0));
//         emit_ins(self, X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

//         self.resolve_jumps();
//         self.result.seal(self.offset_in_text_section)?;

//         // Delete secrets
//         self.environment_stack_key = 0;
//         self.program_argument_key = 0;

//         Ok(())
//     }

func (jit *JitCompiler) generate_prologue(executable *Executable) error {
	// Place the environment on the stack according to EnvironmentStackSlot

	// Save registers
	for _, reg := range CALLEE_SAVED_REGISTERS {
		emit_ins(jit, Push(reg, nil))
	}

	// Initialize CallDepth to 0
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], 0))
	emit_ins(jit, Push(REGISTER_MAP[FRAME_PTR_REG], nil))

	// Initialize the BPF frame and stack pointers (BpfFramePtr and BpfStackPtr)

	if jit.config.DynamicStackFrames {
		// The stack is fully descending from MM_STACK_START + stack_size to MM_STACK_START
		emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START+int64(jit.config.StackSize())))
		// Push BpfFramePtr
		emit_ins(jit, Push(REGISTER_MAP[FRAME_PTR_REG], nil))
		// Push BpfStackPtr
		emit_ins(jit, Push(REGISTER_MAP[FRAME_PTR_REG], nil))
	} else {

		// The frames are ascending from MM_STACK_START to MM_STACK_START + stack_size. The stack within the frames is descending.
		emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START+int64(jit.config.StackFrameSize)))
		// Push BpfFramePtr
		emit_ins(jit, Push(REGISTER_MAP[FRAME_PTR_REG], nil))
		// When using static frames BpfStackPtr is not used
		emit_ins(jit, LoadImmediate(OperandSizeS64, RBP, 0))
		emit_ins(jit, Push(RBP, nil))
	}

	// Save pointer to optional return value
	emit_ins(jit, Push(ARGUMENT_REGISTERS[0], nil))

	// Save initial value of instruction_meter.get_remaining()
	emit_rust_call(jit,
		&Constant64{int64(executable.GetRemaining()), false},
		[]Argument{
			{index: 0, value: &Register{ARGUMENT_REGISTERS[3]}},
		},
		&(ARGUMENT_REGISTERS[0]),
		false,
	)
	emit_ins(jit, Push(ARGUMENT_REGISTERS[0], nil))

	// Save instruction meter
	emit_ins(jit, Push(ARGUMENT_REGISTERS[3], nil))

	// Initialize stop watch
	emit_ins(jit, Alu(OperandSizeS64, 0x31, R11, R11, 0, nil)) // R11 ^= R11;
	emit_ins(jit, Push(R11, nil))
	emit_ins(jit, Push(R11, nil))

	// Initialize frame pointer
	emit_ins(jit, Mov(OperandSizeS64, RSP, RBP))
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RBP, 8*(int64(SlotCount)-1+int64(jit.environmentStackKey)), nil))

	// Save ProgramEnvironment
	emit_ins(jit, Lea(OperandSizeS64, ARGUMENT_REGISTERS[2], R10, X86IndirectAccess_Offset(-jit.programArgumentKey)))

	// Zero BPF registers
	for reg := range REGISTER_MAP {
		if reg != int(REGISTER_MAP[1]) && reg != int(REGISTER_MAP[FRAME_PTR_REG]) {
			emit_ins(jit, LoadImmediate(OperandSizeS64, u8(reg), 0))
		}
	}

	// Jump to entry point
	entry := executable.GetEntrypointInstructionOffset()
	if entry == nil {
		zero := int64(0)
		entry = &zero
	}
	if jit.config.EnableInstructionMeter {
		e := 1
		e += int(*entry)
		emit_profile_instruction_count(jit, &e)
	}
	emit_ins(jit, LoadImmediate(OperandSizeS64, R11, int64(*entry)))
	jump_offset := jit.relativeToTargetPc(int(*entry), 5)
	emit_ins(jit, JumpImmediate(jump_offset))

	return nil
}

func (jit *JitCompiler) generate_subroutines() error {
	// Epilogue
	jit.set_anchor(ANCHOR_EPILOGUE)

	stopwatchResult := func(numerator uint64, denominator uint64) {
		if denominator == 0 {
			fmt.Printf("Stop watch: %d / %d = %f", numerator, denominator, 0.0)
		} else {
			fmt.Printf("Stop watch: %d / %d = %f", numerator, denominator, float64(numerator)/float64(denominator))
		}
	}

	// Print stop watch value
	if jit.stopwatchIsActive {
		emit_rust_call(jit,
			&Constant64{i64(uintptr(unsafe.Pointer(&stopwatchResult))), false},
			[]Argument{
				{index: 1, value: &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, StopwatchDenominator), false}},
				{index: 0, value: &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, StopwatchNumerator), false}},
			}, nil, false)
	}

	// Store instruction_meter in RAX
	emit_ins(jit, Mov(OperandSizeS64, ARGUMENT_REGISTERS[0], RAX))
	// Restore stack pointer in case the BPF stack was used
	emit_ins(jit, Lea(OperandSizeS64, RBP, RSP, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, LastSavedRegister))))
	// Restore registers
	// iterate backwards
	for i := len(CALLEE_SAVED_REGISTERS) - 1; i >= 0; i-- {
		emit_ins(jit, Pop(CALLEE_SAVED_REGISTERS[i]))
	}
	emit_ins(jit, ReturnNear())

	// Routine for instruction tracing
	if jit.config.EnableInstructionTracing {
		jit.set_anchor(ANCHOR_TRACE)
		// Save registers on stack
		emit_ins(jit, Push(R11, nil))
		for i := len(REGISTER_MAP) - 1; i >= 0; i-- {
			emit_ins(jit, Push(REGISTER_MAP[i], nil))
		}
		emit_ins(jit, Mov(OperandSizeS64, RSP, REGISTER_MAP[0]))
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, -8*3, nil)) // RSP -= 8 * 3;
		traceF := new(Tracer).Trace
		emit_rust_call(jit,
			&Constant64{i64(uintptr(unsafe.Pointer(&(traceF)))), false},
			[]Argument{
				{index: 1, value: &Register{REGISTER_MAP[0]}},                                                       // registers
				{index: 0, value: &RegisterPlusConstant32{R10, i32(TRACER_OFFSET) + jit.programArgumentKey, false}}, // jit.tracer
			}, nil, false)
		// Pop stack and return
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, 8*3, nil)) // RSP += 8 * 3;
		emit_ins(jit, Pop(REGISTER_MAP[0]))
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, i64(8*(len(REGISTER_MAP)-1)), nil)) // RSP += 8 * (REGISTER_MAP.len() - 1);
		emit_ins(jit, Pop(R11))
		emit_ins(jit, ReturnNear())
	}

	// Handler for syscall exceptions
	jit.set_anchor(ANCHOR_RUST_EXCEPTION)
	emit_profile_instruction_count_finalize(jit, false)
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EPILOGUE, 5)))

	// Handler for EbpfError::ExceededMaxInstructions
	jit.set_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS)
	emit_set_exception_kind(jit, &ExceededMaxInstructions{0, 0})
	emit_ins(jit, Mov(OperandSizeS64, ARGUMENT_REGISTERS[0], R11))
	emit_profile_instruction_count_finalize(jit, true)
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EPILOGUE, 5)))

	// Handler for exceptions which report their pc
	jit.set_anchor(ANCHOR_EXCEPTION_AT)
	// Validate that we did not reach the instruction meter limit before the exception occured
	if jit.config.EnableInstructionMeter {
		emit_validate_instruction_count(jit, false, nil)
	}
	emit_profile_instruction_count_finalize(jit, true)
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EPILOGUE, 5)))

	// Handler for EbpfError::CallDepthExceeded
	jit.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED)
	emit_set_exception_kind(jit, &CallDepthExceeded{0, 0})
	emit_ins(jit, StoreImmediate(OperandSizeS64, R10, X86IndirectAccess_Offset(24), i64(jit.config.MaxCallDepth))) // depth = jit.config.max_call_depth;
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

	// Handler for EbpfError::CallOutsideTextSegment
	jit.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT)
	emit_set_exception_kind(jit, &CallOutsideTextSegment{0, 0})
	emit_ins(jit, Store(OperandSizeS64, REGISTER_MAP[0], R10, X86IndirectAccess_Offset(24))) // target_address = RAX;
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

	// Handler for EbpfError::DivideByZero
	jit.set_anchor(ANCHOR_DIV_BY_ZERO)
	emit_set_exception_kind(jit, &DivideByZero{0})
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

	// Handler for EbpfError::DivideOverflow
	jit.set_anchor(ANCHOR_DIV_OVERFLOW)
	emit_set_exception_kind(jit, &DivideOverflow{0})
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

	// Handler for EbpfError::UnsupportedInstruction
	jit.set_anchor(ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION)
	// Load BPF target pc from stack (which was saved in ANCHOR_BPF_CALL_REG)
	emit_ins(jit, Load(OperandSizeS64, RSP, R11, X86IndirectAccess_OffsetIndexShift{-16, RSP, 0})) // R11 = RSP[-16];

	// Handler for EbpfError::UnsupportedInstruction
	jit.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION)
	if jit.config.EnableInstructionTracing {
		emit_ins(jit, CallImmediate(jit.relativeToAnchor(ANCHOR_TRACE, 5)))
	}
	emit_set_exception_kind(jit, &UnsupportedInstruction{0})
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

	// Quit gracefully
	jit.set_anchor(ANCHOR_EXIT)
	emit_validate_instruction_count(jit, false, nil)
	emit_profile_instruction_count_finalize(jit, false)
	emit_ins(jit, Load(OperandSizeS64, RBP, R10, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, OptRetValPtr))))
	emit_ins(jit, Store(OperandSizeS64, REGISTER_MAP[0], R10, X86IndirectAccess_Offset(8))) // result.return_value = R0;
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[0], 0))
	emit_ins(jit, Store(OperandSizeS64, REGISTER_MAP[0], R10, X86IndirectAccess_Offset(0))) // result.is_error = false;
	emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EPILOGUE, 5)))

	// Routine for syscall
	//         self.set_anchor(ANCHOR_SYSCALL);
	jit.set_anchor(ANCHOR_SYSCALL)
	//         emit_ins(self, X86Instruction::push(R11, None)); // Padding for stack alignment
	emit_ins(jit, Push(R11, nil)) // Padding for stack alignment
	//         if self.config.enable_instruction_meter {
	//             // RDI = *PrevInsnMeter - RDI;
	//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x2B, ARGUMENT_REGISTERS[0], RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))))); // RDI -= *PrevInsnMeter;
	//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, None)); // RDI = -RDI;
	//             emit_rust_call(self, Value::Constant64(I::consume as *const u8 as i64, false), &[
	//                 Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
	//                 Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
	//             ], None, false);
	//         }
	if jit.config.EnableInstructionMeter {
		// RDI = *PrevInsnMeter - RDI;
		emit_ins(jit, Alu(OperandSizeS64, 0x2B, ARGUMENT_REGISTERS[0], RBP, 0, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, PrevInsnMeter)))) // RDI -= *PrevInsnMeter;
		emit_ins(jit, Alu(OperandSizeS64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, nil))                                                                    // RDI = -RDI;
		consumeF := new(Tracer).Consume
		emit_rust_call(jit,
			&Constant64{i64(uintptr(unsafe.Pointer(&(consumeF)))), false},
			[]Argument{
				{1, &Register{ARGUMENT_REGISTERS[0]}},
				{0, &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, InsnMeterPtr), false}},
			},
			nil,
			false)
	}

	//         emit_rust_call(self, Value::Register(R11), &[
	//             Argument { index: 7, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) },
	//             Argument { index: 6, value: Value::RegisterPlusConstant32(R10, self.program_argument_key, false) }, // jit_program_argument.memory_mapping
	//             Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
	//             Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
	//             Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
	//             Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
	//             Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
	//             Argument { index: 0, value: Value::Register(RAX) }, // "&mut self" in the "call" method of the SyscallObject
	//         ], None, false);
	emit_rust_call(jit,
		&Register{R11},
		[]Argument{
			{7, &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, OptRetValPtr), false}},
			{6, &RegisterPlusConstant32{R10, jit.programArgumentKey, false}}, // jit_program_argument.memory_mapping
			{5, &Register{ARGUMENT_REGISTERS[5]}},
			{4, &Register{ARGUMENT_REGISTERS[4]}},
			{3, &Register{ARGUMENT_REGISTERS[3]}},
			{2, &Register{ARGUMENT_REGISTERS[2]}},
			{1, &Register{ARGUMENT_REGISTERS[1]}},
			{0, &Register{RAX}}, // "&mut self" in the "call" method of the SyscallObject
		},
		nil,
		false)

	//         if self.config.enable_instruction_meter {
	//             emit_rust_call(self, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
	//                 Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
	//             ], Some(ARGUMENT_REGISTERS[0]), false);
	//             emit_ins(self, X86Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))));
	//         }
	if jit.config.EnableInstructionMeter {
		getRemainingF := new(Tracer).GetRemaining
		emit_rust_call(jit,
			&Constant64{i64(uintptr(unsafe.Pointer(&(getRemainingF)))), false},
			[]Argument{
				{0, &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, InsnMeterPtr), false}},
			},
			&ARGUMENT_REGISTERS[0],
			false)
		emit_ins(jit, Store(OperandSizeS64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, PrevInsnMeter))))
	}

	//         emit_ins(self, X86Instruction::pop(R11));
	emit_ins(jit, Pop(R11))
	// Store Ok value in result register
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr))));
	emit_ins(jit, Load(OperandSizeS64, RBP, R11, X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, OptRetValPtr))))
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, R11, REGISTER_MAP[0], X86IndirectAccess::Offset(8)));
	emit_ins(jit, Load(OperandSizeS64, R11, REGISTER_MAP[0], X86IndirectAccess_Offset(8)))
	//         emit_ins(self, X86Instruction::return_near());
	emit_ins(jit, ReturnNear())

	// Routine for prologue of emit_bpf_call()
	//         self.set_anchor(ANCHOR_BPF_CALL_PROLOGUE);
	jit.set_anchor(ANCHOR_BPF_CALL_PROLOGUE)
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 5, RSP, 8 * (SCRATCH_REGS + 1) as i64, None)); // alloca
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 5, RSP, 8*(SCRATCH_REGS+1), nil))
	//         emit_ins(self, X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(0, RSP, 0))); // Save original R11
	emit_ins(jit, Store(OperandSizeS64, R11, RSP, X86IndirectAccess_OffsetIndexShift{0, RSP, 0})) // Save original R11
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS + 1) as i32, RSP, 0))); // Load return address
	emit_ins(jit, Load(OperandSizeS64, RSP, R11, X86IndirectAccess_OffsetIndexShift{8 * (SCRATCH_REGS + 1), RSP, 0})) // Load return address
	//         for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
	//             emit_ins(self, X86Instruction::store(OperandSize::S64, *reg, RSP, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS - i + 1) as i32, RSP, 0))); // Push SCRATCH_REG
	//         }
	for i, reg := range REGISTER_MAP[FIRST_SCRATCH_REG : FIRST_SCRATCH_REG+SCRATCH_REGS] {
		emit_ins(jit, Store(OperandSizeS64, reg, RSP, X86IndirectAccess_OffsetIndexShift{int32(8 * (SCRATCH_REGS - i + 1)), RSP, 0})) // Push SCRATCH_REG
	}
	// Push the caller's frame pointer. The code to restore it is emitted at the end of emit_bpf_call().
	//         emit_ins(self, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RSP, X86IndirectAccess::OffsetIndexShift(8, RSP, 0)));
	emit_ins(jit, Store(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], RSP, X86IndirectAccess_OffsetIndexShift{8, RSP, 0}))
	//         emit_ins(self, X86Instruction::xchg(OperandSize::S64, R11, RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))); // Push return address and restore original R11
	emit_ins(jit, Xchg(OperandSizeS64, R11, RSP, &X86IndirectAccess_OffsetIndexShift{0, RSP, 0})) // Push return address and restore original R11

	// Increase CallDepth
	//         let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
	callDepthAccess := X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, CallDepth))
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 1, Some(call_depth_access)));
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RBP, 1, &callDepthAccess))
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));
	emit_ins(jit, Load(OperandSizeS64, RBP, REGISTER_MAP[FRAME_PTR_REG], callDepthAccess))
	//         // If CallDepth == self.config.max_call_depth, stop and return CallDepthExceeded
	//         emit_ins(self, X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], self.config.max_call_depth as i64, None));
	emit_ins(jit, CmpImmediate(OperandSizeS32, REGISTER_MAP[FRAME_PTR_REG], i64(jit.config.MaxCallDepth), nil))
	//         emit_ins(self, X86Instruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 6)));
	emit_ins(jit, ConditionalJumpImmediate(0x83, jit.relativeToAnchor(ANCHOR_CALL_DEPTH_EXCEEDED, 6)))

	// Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
	//         let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr));
	framePtrAccess := X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, BpfFramePtr))
	//         if self.config.dynamic_stack_frames {
	//             // When dynamic frames are on, the next frame starts at the end of the current frame
	//             let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
	//             emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], stack_ptr_access));
	//             emit_ins(self, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access));
	//         } else {
	//             // With fixed frames we start the new frame at the next fixed offset
	//             let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
	//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, stack_frame_size, Some(frame_ptr_access))); // frame_ptr += stack_frame_size;
	//             emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], frame_ptr_access)); // Load BpfFramePtr
	//         }
	if jit.config.DynamicStackFrames {
		// When dynamic frames are on, the next frame starts at the end of the current frame
		stackPtrAccess := X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, BpfStackPtr))
		emit_ins(jit, Load(OperandSizeS64, RBP, REGISTER_MAP[FRAME_PTR_REG], stackPtrAccess))
		emit_ins(jit, Store(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], RBP, framePtrAccess))
	} else {
		// With fixed frames we start the new frame at the next fixed offset
		var stackFrameSize int64
		if jit.config.EnableStackFrameGaps {
			stackFrameSize = int64(jit.config.StackFrameSize) * 2
		} else {
			stackFrameSize = int64(jit.config.StackFrameSize)
		}
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RBP, stackFrameSize, &framePtrAccess))     // frame_ptr += stack_frame_size;
		emit_ins(jit, Load(OperandSizeS64, RBP, REGISTER_MAP[FRAME_PTR_REG], framePtrAccess)) // Load BpfFramePtr
	}
	//         emit_ins(self, X86Instruction::return_near());
	emit_ins(jit, ReturnNear())

	// Routine for emit_bpf_call(Value::Register())
	//         self.set_anchor(ANCHOR_BPF_CALL_REG);
	jit.set_anchor(ANCHOR_BPF_CALL_REG)
	// Force alignment of RAX
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1), None)); // RAX &= !(INSN_SIZE - 1);
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 4, REGISTER_MAP[0], ^(INSN_SIZE-1), nil)) // RAX &= !(INSN_SIZE - 1);
	// Upper bound check
	//         // if(RAX >= self.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
	//         let number_of_instructions = self.result.pc_section.len() - 1;
	numberOfInstructions := (jit.result.PcSection.Len() / 8) - 1
	//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64));
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], i64(int(jit.programVmAddr)+(numberOfInstructions*INSN_SIZE))))
	//         emit_ins(self, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
	emit_ins(jit, Cmp(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], nil))
	//         emit_ins(self, X86Instruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
	emit_ins(jit, ConditionalJumpImmediate(0x83, jit.relativeToAnchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)))

	// Lower bound check
	//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64));
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], i64(jit.programVmAddr)))
	//         emit_ins(self, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
	emit_ins(jit, Cmp(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], nil))
	//         emit_ins(self, X86Instruction::conditional_jump_immediate(0x82, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
	emit_ins(jit, ConditionalJumpImmediate(0x82, jit.relativeToAnchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)))
	// Calculate offset relative to instruction_addresses
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX -= self.program_vm_addr;
	emit_ins(jit, Alu(OperandSizeS64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, nil)) // RAX -= self.program_vm_addr;
	// Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
	//         let shift_amount = INSN_SIZE.trailing_zeros();
	shiftAmount := u64_(INSN_SIZE).trailing_zeros()
	//         debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
	debug_assert_eq(INSN_SIZE, 1<<shiftAmount, "")
	//         emit_ins(self, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11));
	emit_ins(jit, Mov(OperandSizeS64, REGISTER_MAP[0], R11))
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, shift_amount as i64, None));
	emit_ins(jit, Alu(OperandSizeS64, 0xc1, 5, R11, i64(shiftAmount), nil))
	// Save BPF target pc for potential ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION
	//         emit_ins(self, X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(-8, RSP, 0))); // RSP[-8] = R11;
	emit_ins(jit, Store(OperandSizeS64, R11, RSP, X86IndirectAccess_OffsetIndexShift{-8, RSP, 0})) // RSP[-8] = R11;
	// Load host target_address from self.result.pc_section
	//         debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
	debug_assert_eq(INSN_SIZE, 8, "") // Because the instruction size is also the slot size we do not need to shift the offset
	//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.result.pc_section.as_ptr() as i64));
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[FRAME_PTR_REG], i64(uintptr(jit.result.PcSection.Pointer()))))
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX += self.result.pc_section;
	emit_ins(jit, Alu(OperandSizeS64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, nil)) // RAX += self.result.pc_section;
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0))); // RAX = self.result.pc_section[RAX / 8];
	emit_ins(jit, Load(OperandSizeS64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess_Offset(0))) // RAX = self.result.pc_section[RAX / 8];
	// Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
	//         emit_ins(self, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr))));
	emit_ins(jit, Load(OperandSizeS64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess_Offset(slotOnEnvironmentStack(jit, BpfFramePtr))))
	//         emit_ins(self, X86Instruction::return_near());
	emit_ins(jit, ReturnNear())

	// Translates a host pc back to a BPF pc by linear search of the pc_section table
	//         self.set_anchor(ANCHOR_TRANSLATE_PC);
	jit.set_anchor(ANCHOR_TRANSLATE_PC)
	//         emit_ins(self, X86Instruction::push(REGISTER_MAP[0], None)); // Save REGISTER_MAP[0]
	emit_ins(jit, Push(REGISTER_MAP[0], nil)) // Save REGISTER_MAP[0]
	//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64 - 8)); // Loop index and pointer to look up
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[0], i64(uintptr(jit.result.PcSection.Pointer()))-8)) // Loop index and pointer to look up
	//         self.set_anchor(ANCHOR_TRANSLATE_PC_LOOP); // Loop label
	jit.set_anchor(ANCHOR_TRANSLATE_PC_LOOP) // Loop label
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, REGISTER_MAP[0], 8, None)); // Increase index
	emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, REGISTER_MAP[0], 8, nil)) // Increase index
	//         emit_ins(self, X86Instruction::cmp(OperandSize::S64, R11, REGISTER_MAP[0], Some(X86IndirectAccess::Offset(8)))); // Look up and compare against value at next index
	emit_ins(jit, Cmp(OperandSizeS64, R11, REGISTER_MAP[0], X86IndirectAccess_Offset(8))) // Look up and compare against value at next index
	//         emit_ins(self, X86Instruction::conditional_jump_immediate(0x86, self.relative_to_anchor(ANCHOR_TRANSLATE_PC_LOOP, 6))); // Continue while *REGISTER_MAP[0] <= R11
	emit_ins(jit, ConditionalJumpImmediate(0x86, jit.relativeToAnchor(ANCHOR_TRANSLATE_PC_LOOP, 6))) // Continue while *REGISTER_MAP[0] <= R11
	//         emit_ins(self, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11)); // R11 = REGISTER_MAP[0];
	emit_ins(jit, Mov(OperandSizeS64, REGISTER_MAP[0], R11)) // R11 = REGISTER_MAP[0];
	//         emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64)); // REGISTER_MAP[0] = self.result.pc_section;
	emit_ins(jit, LoadImmediate(OperandSizeS64, REGISTER_MAP[0], i64(uintptr(jit.result.PcSection.Pointer())))) // REGISTER_MAP[0] = self.result.pc_section;
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[0], R11, 0, None)); // R11 -= REGISTER_MAP[0];
	emit_ins(jit, Alu(OperandSizeS64, 0x29, REGISTER_MAP[0], R11, 0, nil)) // R11 -= REGISTER_MAP[0];
	//         emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, 3, None)); // R11 >>= 3;
	emit_ins(jit, Alu(OperandSizeS64, 0xc1, 5, R11, 3, nil)) // R11 >>= 3;
	//         emit_ins(self, X86Instruction::pop(REGISTER_MAP[0])); // Restore REGISTER_MAP[0]
	emit_ins(jit, Pop(REGISTER_MAP[0])) // Restore REGISTER_MAP[0]
	//         emit_ins(self, X86Instruction::return_near());
	emit_ins(jit, ReturnNear())

	// Translates a vm memory address to a host memory address
	//         for (access_type, len) in &[
	//             (AccessType::Load, 1i32),
	//             (AccessType::Load, 2i32),
	//             (AccessType::Load, 4i32),
	//             (AccessType::Load, 8i32),
	//             (AccessType::Store, 1i32),
	//             (AccessType::Store, 2i32),
	//             (AccessType::Store, 4i32),
	//             (AccessType::Store, 8i32),
	//         ] {
	//             let target_offset = len.trailing_zeros() as usize + 4 * (*access_type as usize);
	//             let stack_offset = if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
	//                 24
	//             } else {
	//                 16
	//             };
	for _, v := range []struct {
		AccessType AccessType
		Len        int32
	}{
		{AccessTypeLoad, 1},
		{AccessTypeLoad, 2},
		{AccessTypeLoad, 4},
		{AccessTypeLoad, 8},
		{AccessTypeStore, 1},
		{AccessTypeStore, 2},
		{AccessTypeStore, 4},
		{AccessTypeStore, 8},
	} {
		targetOffset := bits.TrailingZeros32(uint32(v.Len)) + 4*int(v.AccessType)
		stackOffset := 16
		if !jit.config.DynamicStackFrames && jit.config.EnableStackFrameGaps {
			stackOffset = 24
		}

		//             self.set_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset);
		jit.set_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + targetOffset)
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x31, R11, R11, 0, None)); // R11 = 0;
		emit_ins(jit, Alu(OperandSizeS64, 0x31, R11, R11, 0, nil)) // R11 = 0;
		//             emit_ins(self, X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(stack_offset, R11, 0)));
		emit_ins(jit, Load(OperandSizeS64, RSP, R11, X86IndirectAccess_OffsetIndexShift{i32(stackOffset), R11, 0}))
		//             emit_rust_call(self, Value::Constant64(MemoryMapping::generate_access_violation::<UserError> as *const u8 as i64, false), &[
		//                 Argument { index: 3, value: Value::Register(R11) }, // Specify first as the src register could be overwritten by other arguments
		//                 Argument { index: 4, value: Value::Constant64(*len as i64, false) },
		//                 Argument { index: 2, value: Value::Constant64(*access_type as i64, false) },
		//                 Argument { index: 1, value: Value::RegisterPlusConstant32(R10, ProgramEnvironment::MEMORY_MAPPING_OFFSET as i32 + self.program_argument_key, false) }, // jit_program_argument.memory_mapping
		//                 Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) }, // Pointer to optional typed return value
		//             ], None, true);
		generateAccessViolationF := new(MemoryMapping).GenerateAccessViolation
		emit_rust_call(jit, &Constant64{i64(uintptr(unsafe.Pointer(&generateAccessViolationF))), false},
			[]Argument{
				{3, &Register{R11}}, // Specify first as the src register could be overwritten by other arguments
				{4, &Constant64{int64(v.Len), false}},
				{2, &Constant64{int64(v.AccessType), false}},
				{1, &RegisterPlusConstant32{R10, MEMORY_MAPPING_OFFSET + jit.programArgumentKey, false}}, // jit_program_argument.memory_mapping
				{0, &RegisterIndirect{RBP, slotOnEnvironmentStack(jit, OptRetValPtr), false}},            // Pointer to optional typed return value
			}, nil, true)
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, stack_offset as i64 + 8, None)); // Drop R11, RAX, RCX, RDX from stack
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, int64(stackOffset+8), nil)) // Drop R11, RAX, RCX, RDX from stack
		//             emit_ins(self, X86Instruction::pop(R11)); // Put callers PC in R11
		emit_ins(jit, Pop(R11)) // Put callers PC in R11
		//             emit_ins(self, X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_TRANSLATE_PC, 5)));
		emit_ins(jit, CallImmediate(jit.relativeToAnchor(ANCHOR_TRANSLATE_PC, 5)))
		//             emit_ins(self, X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));
		emit_ins(jit, JumpImmediate(jit.relativeToAnchor(ANCHOR_EXCEPTION_AT, 5)))

		//             self.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
		jit.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + targetOffset)
		//             emit_ins(self, X86Instruction::push(R11, None));
		emit_ins(jit, Push(R11, nil))
		//             emit_ins(self, X86Instruction::push(RAX, None));
		emit_ins(jit, Push(RAX, nil))
		//             emit_ins(self, X86Instruction::push(RCX, None));
		emit_ins(jit, Push(RCX, nil))
		//             if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
		//                 emit_ins(self, X86Instruction::push(RDX, None));
		//             }
		if !jit.config.DynamicStackFrames && jit.config.EnableStackFrameGaps {
			emit_ins(jit, Push(RDX, nil))
		}
		//             emit_ins(self, X86Instruction::mov(OperandSize::S64, R11, RAX)); // RAX = vm_addr;
		emit_ins(jit, Mov(OperandSizeS64, R11, RAX)) // RAX = vm_addr;
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 5, RAX, ebpf::VIRTUAL_ADDRESS_BITS as i64, None)); // RAX >>= ebpf::VIRTUAL_ADDRESS_BITS;
		emit_ins(jit, Alu(OperandSizeS64, 0xc1, 5, RAX, VIRTUAL_ADDRESS_BITS, nil)) // RAX >>= ebpf::VIRTUAL_ADDRESS_BITS;
		//             emit_ins(self, X86Instruction::cmp(OperandSize::S64, RAX, R10, Some(X86IndirectAccess::Offset(self.program_argument_key + 8)))); // region_index >= jit_program_argument.memory_mapping.regions.len()
		emit_ins(jit, Cmp(OperandSizeS64, RAX, R10, X86IndirectAccess_Offset(jit.programArgumentKey+8))) // region_index >= jit_program_argument.memory_mapping.regions.len()
		//             emit_ins(self, X86Instruction::conditional_jump_immediate(0x86, self.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
		emit_ins(jit, ConditionalJumpImmediate(0x86, jit.relativeToAnchor(uint(ANCHOR_MEMORY_ACCESS_VIOLATION+targetOffset), 6)))
		//             debug_assert_eq!(1 << 5, mem::size_of::<MemoryRegion>());
		debug_assert_eq(1<<5, unsafe.Sizeof(MemoryRegion{}), "1 << 5 != unsafe.Sizeof(MemoryRegion{})")
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 4, RAX, 5, None)); // RAX *= mem::size_of::<MemoryRegion>();
		emit_ins(jit, Alu(OperandSizeS64, 0xc1, 4, RAX, 5, nil)) // RAX *= mem::size_of::<MemoryRegion>();
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x03, RAX, R10, 0, Some(X86IndirectAccess::Offset(self.program_argument_key)))); // region = &jit_program_argument.memory_mapping.regions[region_index];
		emit_ins(jit, Alu(OperandSizeS64, 0x03, RAX, R10, 0, X86IndirectAccess_Offset(jit.programArgumentKey))) // region = &jit_program_argument.memory_mapping.regions[region_index];
		//             if *access_type == AccessType::Store {
		//                 emit_ins(self, X86Instruction::cmp_immediate(OperandSize::S8, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::IS_WRITABLE_OFFSET)))); // region.is_writable == 0
		//                 emit_ins(self, X86Instruction::conditional_jump_immediate(0x84, self.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
		//             }
		if v.AccessType == AccessTypeStore {
			emit_ins(jit, CmpImmediate(OperandSizeS8, RAX, 0, X86IndirectAccess_Offset(IS_WRITABLE_OFFSET))) // region.is_writable == 0
			emit_ins(jit, ConditionalJumpImmediate(0x84, jit.relativeToAnchor(uint(ANCHOR_MEMORY_ACCESS_VIOLATION+targetOffset), 6)))
		}

		//             emit_ins(self, X86Instruction::load(OperandSize::S64, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_ADDR_OFFSET))); // RCX = region.vm_addr
		emit_ins(jit, Load(OperandSizeS64, RAX, RCX, X86IndirectAccess_Offset(VM_ADDR_OFFSET))) // RCX = region.vm_addr
		//             emit_ins(self, X86Instruction::cmp(OperandSize::S64, RCX, R11, None)); // vm_addr < region.vm_addr
		emit_ins(jit, Cmp(OperandSizeS64, RCX, R11, nil)) // vm_addr < region.vm_addr
		//             emit_ins(self, X86Instruction::conditional_jump_immediate(0x82, self.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
		emit_ins(jit, ConditionalJumpImmediate(0x82, jit.relativeToAnchor(uint(ANCHOR_MEMORY_ACCESS_VIOLATION+targetOffset), 6)))
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x29, RCX, R11, 0, None)); // vm_addr -= region.vm_addr
		emit_ins(jit, Alu(OperandSizeS64, 0x29, RCX, R11, 0, nil)) // vm_addr -= region.vm_addr
		//             if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
		//                 emit_ins(self, X86Instruction::load(OperandSize::S8, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_GAP_SHIFT_OFFSET))); // RCX = region.vm_gap_shift;
		//                 emit_ins(self, X86Instruction::mov(OperandSize::S64, R11, RDX)); // RDX = R11;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xd3, 5, RDX, 0, None)); // RDX = R11 >> region.vm_gap_shift;
		//                 emit_ins(self, X86Instruction::test_immediate(OperandSize::S64, RDX, 1, None)); // (RDX & 1) != 0
		//                 emit_ins(self, X86Instruction::conditional_jump_immediate(0x85, self.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
		//                 emit_ins(self, X86Instruction::load_immediate(OperandSize::S64, RDX, -1)); // RDX = -1;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xd3, 4, RDX, 0, None)); // gap_mask = -1 << region.vm_gap_shift;
		//                 emit_ins(self, X86Instruction::mov(OperandSize::S64, RDX, RCX)); // RCX = RDX;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xf7, 2, RCX, 0, None)); // inverse_gap_mask = !gap_mask;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x21, R11, RCX, 0, None)); // below_gap = R11 & inverse_gap_mask;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x21, RDX, R11, 0, None)); // above_gap = R11 & gap_mask;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, 1, None)); // above_gap >>= 1;
		//                 emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x09, RCX, R11, 0, None)); // gapped_offset = above_gap | below_gap;
		//             }
		if !jit.config.DynamicStackFrames && jit.config.EnableStackFrameGaps {
			emit_ins(jit, Load(OperandSizeS8, RAX, RCX, X86IndirectAccess_Offset(VM_GAP_SHIFT_OFFSET))) // RCX = region.vm_gap_shift;
			emit_ins(jit, Mov(OperandSizeS64, R11, RDX))                                                // RDX = R11;
			emit_ins(jit, Alu(OperandSizeS64, 0xd3, 5, RDX, 0, nil))                                    // RDX = R11 >> region.vm_gap_shift;
			emit_ins(jit, TestImmediate(OperandSizeS64, RDX, 1, nil))                                   // (RDX & 1) != 0
			emit_ins(jit, ConditionalJumpImmediate(0x85, jit.relativeToAnchor(uint(ANCHOR_MEMORY_ACCESS_VIOLATION+targetOffset), 6)))
			emit_ins(jit, LoadImmediate(OperandSizeS64, RDX, -1))      // RDX = -1;
			emit_ins(jit, Alu(OperandSizeS64, 0xd3, 4, RDX, 0, nil))   // gap_mask = -1 << region.vm_gap_shift;
			emit_ins(jit, Mov(OperandSizeS64, RDX, RCX))               // RCX = RDX;
			emit_ins(jit, Alu(OperandSizeS64, 0xf7, 2, RCX, 0, nil))   // inverse_gap_mask = !gap_mask;
			emit_ins(jit, Alu(OperandSizeS64, 0x21, R11, RCX, 0, nil)) // below_gap = R11 & inverse_gap_mask;
			emit_ins(jit, Alu(OperandSizeS64, 0x21, RDX, R11, 0, nil)) // above_gap = R11 & gap_mask;
			emit_ins(jit, Alu(OperandSizeS64, 0xc1, 5, R11, 1, nil))   // above_gap >>= 1;
			emit_ins(jit, Alu(OperandSizeS64, 0x09, RCX, R11, 0, nil)) // gapped_offset = above_gap | below_gap;
		}

		//             emit_ins(self, X86Instruction::lea(OperandSize::S64, R11, RCX, Some(X86IndirectAccess::Offset(*len)))); // RCX = R11 + len;
		//             emit_ins(self, X86Instruction::cmp(OperandSize::S64, RCX, RAX, Some(X86IndirectAccess::Offset(MemoryRegion::LEN_OFFSET)))); // region.len < R11 + len
		//             emit_ins(self, X86Instruction::conditional_jump_immediate(0x82, self.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x03, R11, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::HOST_ADDR_OFFSET)))); // R11 += region.host_addr;
		//             if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
		//                 emit_ins(self, X86Instruction::pop(RDX));
		//             }
		//             emit_ins(self, X86Instruction::pop(RCX));
		//             emit_ins(self, X86Instruction::pop(RAX));
		//             emit_ins(self, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8, None));
		//             emit_ins(self, X86Instruction::return_near());
		//         }
		emit_ins(jit, Lea(OperandSizeS64, R11, RCX, X86IndirectAccess_Offset(v.Len)))      // RCX = R11 + len;
		emit_ins(jit, Cmp(OperandSizeS64, RCX, RAX, X86IndirectAccess_Offset(LEN_OFFSET))) // region.len < R11 + len
		emit_ins(jit, ConditionalJumpImmediate(0x82, jit.relativeToAnchor(uint(ANCHOR_MEMORY_ACCESS_VIOLATION+targetOffset), 6)))
		emit_ins(jit, Alu(OperandSizeS64, 0x03, R11, RAX, 0, X86IndirectAccess_Offset(HOST_ADDR_OFFSET))) // R11 += region.host_addr;
		if !jit.config.DynamicStackFrames && jit.config.EnableStackFrameGaps {
			emit_ins(jit, Pop(RDX))
		}
		emit_ins(jit, Pop(RCX))
		emit_ins(jit, Pop(RAX))
		emit_ins(jit, Alu(OperandSizeS64, 0x81, 0, RSP, 8, nil))
		emit_ins(jit, ReturnNear())
	}
	return nil
}

func (jit *JitCompiler) set_anchor(anchor int) {
	instructionEnd := unsafe.Add(jit.result.TextSection.Pointer(), uintptr(jit.offsetInTextSection))
	jit.anchors[anchor] = instructionEnd
}

func (jit *JitCompiler) relativeToAnchor(anchor uint, instructionLength uint) int32 {
	// TODO: Check if this is correct
	instructionEnd := unsafe.Add(jit.result.TextSection.Pointer(), uintptr(jit.offsetInTextSection)+uintptr(instructionLength))
	destination := jit.anchors[anchor]
	if destination == nil {
		panic("destination is nil")
	}
	return int32(uintptr(destination) - uintptr(instructionEnd)) // Relative jump
}

func (jit *JitCompiler) relativeToTargetPc(targetPc int, instructionLength int) int32 {
	// TODO: test
	instructionEnd := unsafe.Add(jit.result.TextSection.Pointer(), uintptr(jit.offsetInTextSection)+uintptr(instructionLength))
	var destination uintptr
	if jit.result.PcSection.Uint64SliceGetByIndex(u64(targetPc)) != 0 {
		// Backward jump
		destination = uintptr(jit.result.PcSection.Uint64SliceGetByIndex(u64(targetPc)))
	} else {
		// Forward jump, needs relocation
		jit.textSectionJumps = append(jit.textSectionJumps, &JitJump{location: unsafe.Add(instructionEnd, -4), target_pc: targetPc})
		// TODO: what this return means?
		return 0
	}
	debug_assert(destination != 0, "destination is nil")
	// TODO: is this correct?
	// (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
	return int32(destination - uintptr(instructionEnd)) // Relative jump
}

func (jit *JitCompiler) resolve_jumps() {
	// Relocate forward jumps
	for _, jump := range jit.textSectionJumps {
		destination := jit.result.PcSection.Uint64SliceGetByIndex(u64(jump.target_pc))
		// TODO: is this correct?
		offsetValue := unsafe.Add(unsafe.Pointer(&destination), -uintptr(jump.location)-4) // Jump from end of instruction
		jump.location = offsetValue
	}

	// There is no `VerifierError::JumpToMiddleOfLDDW` for `call imm` so patch it here
	callUnsupportedInstruction := jit.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION]
	callxUnsupportedInstruction := jit.anchors[ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION]
	for i := 0; i < jit.result.PcSection.Len()/8; i++ {
		if jit.result.PcSection.Uint64SliceGetByIndex(u64(i)) == u64(uintptr(callUnsupportedInstruction)) {
			jit.result.PcSection.Uint64SliceSetByIndex(u64(i), u64(uintptr(callxUnsupportedInstruction)))
		}
	}
}
