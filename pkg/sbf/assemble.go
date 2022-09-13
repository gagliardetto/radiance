package sbf

type Instruction interface {
	// Assemble assembles the Instruction into a RawInstruction.
	Assemble() (RawInstruction, error)
}

type RawInstruction []byte

// Lddw loads a 64-bit immediate value into a register.
type Lddw struct {
	// Destination register.
	Dst uint8
	// Constant value.
	Imm uint64
}

func (i Lddw) Assemble() (RawInstruction, error) {
	return RawInstruction{
		OpLddw,
		i.Dst,
		byte(i.Imm),
		byte(i.Imm >> 8),
		byte(i.Imm >> 16),
		byte(i.Imm >> 24),
		byte(i.Imm >> 32),
		byte(i.Imm >> 40),
		byte(i.Imm >> 48),
		byte(i.Imm >> 56),
	}, nil
}

// Ldxb loads a byte from memory.
type Ldxb struct {
	// Destination register.
	Dst uint8
	// Source register.
	Src uint8
	// Offset from the value in Src.
	Off int16
}

func (i Ldxb) Assemble() (RawInstruction, error) {
	return RawInstruction{
		OpLdxb,
		i.Dst,
		i.Src,
		byte(i.Off),
		byte(i.Off >> 8),
	}, nil
}

type RawInstructions []RawInstruction

func (i RawInstructions) Code() []byte {
	var code []byte
	for _, ins := range i {
		code = append(code, ins...)
	}
	return code
}

// func Run(instructions RawInstructions, input []byte) ([]byte, error) {
// 	// concat all instructions into one byte slice
// 	code := instructions.Code()
// 	// create program
// 	l, err := loader.NewLoaderFromBytes(code)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// load program
// 	p, err := l.Load()
// 	if err != nil {
// 		return nil, err
// 	}
// 	// verify program
// 	if err := p.Verify(); err != nil {
// 		return nil, err
// 	}
// 	// sycalls
// 	syscalls := NewSyscallRegistry()
// 	syscalls.Register("log", sealevel.SyscallLog)
// 	syscalls.Register("log_64", sealevel.SyscallLog64)

// 	var log sealevel.LogRecorder
// 	// run program
// 	opts := VMOpts{
// 		HeapSize: 32 * 1024,
// 		Input:    input,
// 		MaxCU:    10000,
// 		Syscalls: syscalls,
// 		Context:  &sealevel.Execution{Log: &log},
// 	}
// 	intrpr := NewInterpreter(p, opts)
// 	return input, intrpr.Run()
// }

// Assemble assembles the given instructions into a RawInstruction.
func Assemble(instructions []Instruction) ([]RawInstruction, error) {
	var out []RawInstruction
	for _, ins := range instructions {
		raw, err := ins.Assemble()
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}
