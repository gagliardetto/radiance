// ported from https://github.com/solana-labs/rbpf/blob/v0.2.32/src/x86.rs
package sbf

import (
	"math"
	"reflect"
)

const (
	RAX uint8 = iota
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// System V AMD64 ABI
// Works on: Linux, macOS, BSD and Solaris but not on Windows
var ARGUMENT_REGISTERS [6]uint8 = [6]uint8{RDI, RSI, RDX, RCX, R8, R9}
var CALLER_SAVED_REGISTERS [9]uint8 = [9]uint8{RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11}
var CALLEE_SAVED_REGISTERS [6]uint8 = [6]uint8{RBP, RBX, R12, R13, R14, R15}

// TODO: add exclude_operand_sizes

type X86Rex struct {
	w bool
	r bool
	x bool
	b bool
}

type X86ModRm struct {
	mode uint8
	r    uint8
	m    uint8
}

type X86Sib struct {
	scale uint8
	index uint8
	base  uint8
}

type X86IndirectAccess interface {
	isX86IndirectAccess()
}

var _ X86IndirectAccess = X86IndirectAccess_Offset(0)
var _ X86IndirectAccess = X86IndirectAccess_OffsetIndexShift{0, 0, 0}

// [second_operand + offset]
type X86IndirectAccess_Offset int32

func (X86IndirectAccess_Offset) isX86IndirectAccess() {}

// [second_operand + offset + index << shift]
type X86IndirectAccess_OffsetIndexShift struct {
	Offset int32
	Index  uint8
	Shift  uint8
}

func (X86IndirectAccess_OffsetIndexShift) isX86IndirectAccess() {}

type FenceType int

const (
	// lfence
	FenceTypeLoad FenceType = 5
	// mfence
	FenceTypeAll FenceType = 6
	// sfence
	FenceTypeStore FenceType = 7
)

type X86Instruction struct {
	size                 OperandSize
	opcodeEscapeSequence uint8
	opcode               uint8
	modrm                bool
	indirect             X86IndirectAccess
	firstOperand         uint8
	secondOperand        uint8
	immediateSize        OperandSize
	immediate            int64
}

func NewDefaultX86Instruction() X86Instruction {
	return X86Instruction{
		size:                 S0,
		opcodeEscapeSequence: 0,
		opcode:               0,
		modrm:                true,
		indirect:             nil, // None
		firstOperand:         0,
		secondOperand:        0,
		immediateSize:        S0,
		immediate:            0,
	}
}

func (self *X86Instruction) Emit(jit *JitCompiler) {
	debug_assert(self.size != S0, "size must be set")

	rex := X86Rex{
		w: matches(self.size, S64),
		r: self.firstOperand&0b1000 != 0,
		x: false,
		b: self.secondOperand&0b1000 != 0,
	}
	modrm := X86ModRm{
		mode: 0,
		r:    self.firstOperand & 0b111,
		m:    self.secondOperand & 0b111,
	}
	sib := X86Sib{
		scale: 0,
		index: 0,
		base:  0,
	}
	displacementSize := S0
	displacement := int32(0)
	if self.modrm {
		if self.indirect != nil {
			switch indirect := self.indirect.(type) {
			case *X86IndirectAccess_Offset:
				{
					displacement = int32(*indirect)
					debug_assert_ne(self.secondOperand&0b111, RSP, "") // Reserved for SIB addressing
					if -128 <= displacement && displacement <= 127 || (displacement == 0 && self.secondOperand&0b111 == RBP) {
						displacementSize = S8
						modrm.mode = 1
					} else {
						displacementSize = S32
						modrm.mode = 2
					}
				}
			case *X86IndirectAccess_OffsetIndexShift:
				displacement = indirect.Offset
				displacementSize = S32
				modrm.mode = 2
				modrm.m = RSP
				rex.x = indirect.Index&0b1000 != 0
				sib.scale = indirect.Shift & 0b11
				sib.index = indirect.Index & 0b111
				sib.base = self.secondOperand & 0b111
			default:
				modrm.mode = 3
			}
		}
	}
	if self.size == S16 {
		emit(jit, u8(0x66))
	}
	rex_ := ((boolAsU8(rex.w)) << 3) | ((boolAsU8(rex.r)) << 2) | ((boolAsU8(rex.x)) << 1) | (boolAsU8(rex.b))
	if rex_ != 0 {
		emit(jit, u8(0x40|rex_))
	}
	switch self.opcodeEscapeSequence {
	case 1:
		emit(jit, u8(0x0f))
	case 2:
		emit(jit, u16(0x0f38))
	case 3:
		emit(jit, u16(0x0f3a))
	default:
	}
	emit(jit, self.opcode)
	if self.modrm {
		emit(jit, u8(modrm.mode<<6)|(modrm.r<<3)|modrm.m)
		sib := (sib.scale << 6) | (sib.index << 3) | sib.base
		if sib != 0 {
			emit(jit, sib)
		}
		emitVariableLength(jit, displacementSize, u64(displacement))
	}
	emitVariableLength(jit, self.immediateSize, u64(self.immediate))
}

// Arithmetic or logic
func Alu(
	size OperandSize,
	opcode uint8,
	source uint8,
	destination uint8,
	immediate int64,
	indirect X86IndirectAccess,
) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0|OperandSizeS8|OperandSizeS16)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = opcode
	ins.firstOperand = source
	ins.secondOperand = destination
	ins.immediate = immediate
	ins.immediateSize = func() OperandSize {
		switch opcode {
		case 0xc1:
			return OperandSizeS8
		case 0x81:
			return OperandSizeS32
		case 0xf7:
			if source == 0 {
				return OperandSizeS32
			}
		}
		return OperandSizeS0
	}()
	ins.indirect = indirect
	return &ins
}

// Move source to destination
func Mov(size OperandSize, source uint8, destination uint8) *X86Instruction {
	// exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = 0x89
	ins.firstOperand = source
	ins.secondOperand = destination
	return &ins
}

// Conditionally move source to destination
func Cmov(size OperandSize, condition uint8, source uint8, destination uint8) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0|OperandSizeS8|OperandSizeS16)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcodeEscapeSequence = 1
	ins.opcode = condition
	ins.firstOperand = destination
	ins.secondOperand = source
	return &ins
}

// Swap source and destination
func Xchg(size OperandSize, source uint8, destination uint8, indirect X86IndirectAccess) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0|OperandSizeS8|OperandSizeS16|OperandSizeS32)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = 0x87
	ins.firstOperand = source
	ins.secondOperand = destination
	ins.indirect = indirect
	return &ins
}

// Swap byte order of destination
func Bswap(size OperandSize, destination byte) *X86Instruction {
	switch size {
	case OperandSizeS16:
		ins := NewDefaultX86Instruction()
		ins.size = size
		ins.opcode = 0xc1
		ins.secondOperand = destination
		ins.immediateSize = OperandSizeS8
		ins.immediate = 8
		return &ins
	case OperandSizeS32, OperandSizeS64:
		ins := NewDefaultX86Instruction()
		ins.size = size
		ins.opcodeEscapeSequence = 1
		ins.opcode = 0xc8 | (destination & 0b111)
		ins.modrm = false
		ins.secondOperand = destination
		return &ins
	default:
		panic("unimplemented")
	}
}

// Test source and destination
func Test(size OperandSize, source uint8, destination uint8, indirect X86IndirectAccess) *X86Instruction {
	// exclude_operand_sizes!(size, OperandSize::S0)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		if size == OperandSizeS8 {
			return 0x84
		}
		return 0x85
	}()
	ins.firstOperand = source
	ins.secondOperand = destination
	ins.indirect = indirect
	return &ins
}

// Test immediate and destination
func TestImmediate(size OperandSize, destination uint8, immediate int64, indirect X86IndirectAccess) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		if size == OperandSizeS8 {
			return 0xf6
		}
		return 0xf7
	}()
	ins.firstOperand = RAX
	ins.secondOperand = destination
	ins.immediateSize = func() OperandSize {
		if size == OperandSizeS64 {
			return OperandSizeS32
		}
		return size
	}()
	ins.immediate = immediate
	ins.indirect = indirect
	return &ins
}

// Compare source and destination
func Cmp(size OperandSize, source, destination uint8, indirect X86IndirectAccess) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		if size == OperandSizeS8 {
			return 0x38
		}
		return 0x39
	}()
	ins.firstOperand = source
	ins.secondOperand = destination
	ins.indirect = indirect
	return &ins
}

// Compare immediate and destination
func CmpImmediate(size OperandSize, destination uint8, immediate int64, indirect X86IndirectAccess) *X86Instruction {
	// exclude_operand_sizes!(size, OperandSize::S0);
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		if size == OperandSizeS8 {
			return 0x80
		}
		return 0x81
	}()
	ins.firstOperand = RDI
	ins.secondOperand = destination
	ins.immediateSize = func() OperandSize {
		if size == OperandSizeS64 {
			return OperandSizeS32
		}
		return size
	}()
	ins.immediate = immediate
	ins.indirect = indirect
	return &ins
}

// Load effective address of source into destination
func Lea(size OperandSize, source uint8, destination uint8, indirect X86IndirectAccess) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = 0x8d
	ins.firstOperand = destination
	ins.secondOperand = source
	ins.indirect = indirect
	return &ins
}

// Convert word to doubleword or doubleword to quadword
func DividendSignExtension(size OperandSize) *X86Instruction {
	// exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = 0x99
	ins.modrm = false
	return &ins
}

// Load destination from [source + offset]
func Load(size OperandSize, source, destination uint8, indirect X86IndirectAccess) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0)
	ins := NewDefaultX86Instruction()
	ins.size = func() OperandSize {
		if size == OperandSizeS64 {
			return OperandSizeS64
		}
		return OperandSizeS32
	}()
	ins.opcodeEscapeSequence = func() uint8 {
		if size == OperandSizeS8 || size == OperandSizeS16 {
			return 1
		}
		return 0
	}()
	ins.opcode = func() uint8 {
		if size == OperandSizeS8 {
			return 0xb6
		}
		if size == OperandSizeS16 {
			return 0xb7
		}
		return 0x8b // TODO: is this correct?
	}()
	ins.firstOperand = destination
	ins.secondOperand = source
	ins.indirect = indirect
	return &ins
}

// Store source in [destination + offset]
func Store(
	size OperandSize,
	source u8,
	destination u8,
	indirect X86IndirectAccess,
) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0)
	val := NewDefaultX86Instruction()
	val.size = size
	val.opcode = func() uint8 {
		switch size {
		case OperandSizeS8:
			return 0x88
		default:
			return 0x89
		}
	}()
	val.firstOperand = source
	val.secondOperand = destination
	val.indirect = indirect
	return &val
}

// Load destination from sign-extended immediate
func LoadImmediate(size OperandSize, destination uint8, immediate int64) *X86Instruction {
	// excludeOperandSizes!(size, OperandSizeS0 | OperandSizeS8 | OperandSizeS16)
	var immediateSize OperandSize
	if immediate >= int64(math.MinInt32) && immediate <= int64(math.MaxInt32) {
		immediateSize = OperandSizeS32
	} else {
		immediateSize = OperandSizeS64
	}
	switch immediateSize {
	case OperandSizeS32:
		ins := NewDefaultX86Instruction()
		ins.size = size
		ins.opcode = 0xc7
		ins.secondOperand = destination
		ins.immediateSize = OperandSizeS32
		ins.immediate = immediate
		return &ins
	case OperandSizeS64:
		ins := NewDefaultX86Instruction()
		ins.size = size
		ins.opcode = 0xb8 | (destination & 0b111)
		ins.modrm = false
		ins.secondOperand = destination
		ins.immediateSize = OperandSizeS64
		ins.immediate = immediate
		return &ins
	default:
		panic("unimplemented!")
	}
}

// Store sign-extended immediate in destination
func StoreImmediate(size OperandSize, destination uint8, indirect X86IndirectAccess, immediate int64) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		switch size {
		case OperandSizeS8:
			return 0xc6
		default:
			return 0xc7
		}
	}()
	ins.secondOperand = destination
	ins.indirect = indirect
	ins.immediateSize = func() OperandSize {
		if size == OperandSizeS64 {
			return OperandSizeS32
		}
		return size
	}()
	ins.immediate = immediate
	return &ins
}

// Push source onto the stack
func PushImmediate(size OperandSize, immediate int32) *X86Instruction {
	// excludeOperandSizes(size, OperandSizeS0|OperandSizeS16)
	ins := NewDefaultX86Instruction()
	ins.size = size
	ins.opcode = func() uint8 {
		switch size {
		case OperandSizeS8:
			return 0x6A
		default:
			return 0x68
		}
	}()
	ins.modrm = false
	ins.immediateSize = func() OperandSize {
		if size == OperandSizeS64 {
			return OperandSizeS32
		}
		return size
	}()
	ins.immediate = int64(immediate)
	return &ins
}

// Push source onto the stack
func Push(source uint8, indirect X86IndirectAccess) *X86Instruction {
	if isNone(indirect) {
		ins := NewDefaultX86Instruction()
		ins.size = OperandSizeS32
		ins.opcode = 0x50 | (source & 0b111)
		ins.modrm = false
		ins.secondOperand = source
		return &ins
	} else {
		ins := NewDefaultX86Instruction()
		ins.size = OperandSizeS64
		ins.opcode = 0xFF
		ins.modrm = true
		ins.firstOperand = 6
		ins.secondOperand = source
		ins.indirect = indirect
		return &ins
	}
}

func isNone(x any) (b bool) {
	defer func(b bool) {
		if err := recover(); err != nil {
			b = true
		}
	}(b)
	return x == nil || (reflect.ValueOf(x).Kind() == reflect.Ptr && reflect.ValueOf(x).IsNil())
}

// Pop from the stack into destination
func Pop(destination uint8) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0x58 | (destination & 0b111)
	ins.modrm = false
	ins.secondOperand = destination
	return &ins
}

// Jump to relative destination on condition
func ConditionalJumpImmediate(opcode uint8, relativeDestination int32) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcodeEscapeSequence = 1
	ins.opcode = opcode
	ins.modrm = false
	ins.immediateSize = OperandSizeS32
	ins.immediate = int64(relativeDestination)
	return &ins
}

// Jump to relative destination
func JumpImmediate(relativeDestination int32) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0xe9
	ins.modrm = false
	ins.immediateSize = OperandSizeS32
	ins.immediate = int64(relativeDestination)
	return &ins
}

// Push RIP and jump to relative destination
func CallImmediate(relativeDestination int32) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0xe8
	ins.modrm = false
	ins.immediateSize = OperandSizeS32
	ins.immediate = int64(relativeDestination)
	return &ins
}

// Push RIP and jump to absolute destination
func CallReg(destination byte, indirect X86IndirectAccess) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS64
	ins.opcode = 0xff
	ins.firstOperand = 2
	ins.secondOperand = destination
	ins.indirect = indirect
	return &ins
}

// Pop RIP
func ReturnNear() *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0xc3
	ins.modrm = false
	return &ins
}

// No operation
func Noop() *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0x90
	ins.modrm = false
	return &ins
}

// Trap / software interrupt
func Interrupt(immediate uint8) *X86Instruction {
	ins := NewDefaultX86Instruction()
	if immediate == 3 {
		ins.size = OperandSizeS32
		ins.opcode = 0xcc
		ins.modrm = false
	} else {
		ins.size = OperandSizeS32
		ins.opcode = 0xcd
		ins.modrm = false
		ins.immediateSize = OperandSizeS8
		ins.immediate = int64(immediate)
	}
	return &ins
}

// rdtsc
func CycleCount() *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcodeEscapeSequence = 1
	ins.opcode = 0x31
	ins.modrm = false
	return &ins
}

// lfence / sfence / mfence
func Fence(fenceType FenceType) *X86Instruction {
	ins := NewDefaultX86Instruction()
	ins.size = OperandSizeS32
	ins.opcode = 0xae
	ins.opcodeEscapeSequence = 1
	ins.firstOperand = uint8(fenceType)
	return &ins
}
