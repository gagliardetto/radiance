package sbf

import "fmt"

// User defined errors must implement this trait
type UserDefinedError interface {
	Error() string
}

// Error definitions
type EbpfError interface {
	error
	isEbpfError()
	ErrorKindIndex() int
}

var (
	_ EbpfError = &UserError{}
	_ EbpfError = &ElfError{}
	_ EbpfError = &SyscallAlreadyRegistered{}
	_ EbpfError = &SyscallNotRegistered{}
	_ EbpfError = &SyscallAlreadyBound{}
	_ EbpfError = &TooManySyscalls{}
	_ EbpfError = &CallDepthExceeded{}
	_ EbpfError = &ExitRootCallFrame{}
	_ EbpfError = &DivideByZero{}
	_ EbpfError = &DivideOverflow{}
	_ EbpfError = &ExecutionOverrun{}
	_ EbpfError = &CallOutsideTextSegment{}
	_ EbpfError = &ExceededMaxInstructions{}
	_ EbpfError = &JitNotCompiled{}
	_ EbpfError = &InvalidVirtualAddress{}
	_ EbpfError = &InvalidMemoryRegion{}
	_ EbpfError = &AccessViolation{}
	_ EbpfError = &StackAccessViolation{}
	_ EbpfError = &InvalidInstruction{}
	_ EbpfError = &UnsupportedInstruction{}
	_ EbpfError = &ExhaustedTextSegment{}
	_ EbpfError = &LibcInvocationFailed{}
	_ EbpfError = &VerifierError{}
)

func ErrorKindIndexToErrorName(index int) string {
	switch index {
	case 0:
		return "UserError"
	case 1:
		return "ElfError"
	case 2:
		return "SyscallAlreadyRegistered"
	case 3:
		return "SyscallNotRegistered"
	case 4:
		return "SyscallAlreadyBound"
	case 5:
		return "TooManySyscalls"
	case 6:
		return "CallDepthExceeded"
	case 7:
		return "ExitRootCallFrame"
	case 8:
		return "DivideByZero"
	case 9:
		return "DivideOverflow"
	case 10:
		return "ExecutionOverrun"
	case 11:
		return "CallOutsideTextSegment"
	case 12:
		return "ExceededMaxInstructions"
	case 13:
		return "JitNotCompiled"
	case 14:
		return "InvalidVirtualAddress"
	case 15:
		return "InvalidMemoryRegion"
	case 16:
		return "AccessViolation"
	case 17:
		return "StackAccessViolation"
	case 18:
		return "InvalidInstruction"
	case 19:
		return "UnsupportedInstruction"
	case 20:
		return "ExhaustedTextSegment"
	case 21:
		return "LibcInvocationFailed"
	case 22:
		return "VerifierError"
	default:
		return "unknown error"
	}
}

// User defined error
type UserError struct {
	Err error
}

func (e *UserError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("user error: %s", e.Err.Error())
	}
	return "user error"
}

func (e *UserError) isEbpfError() {}
func (e *UserError) ErrorKindIndex() int {
	return 0
}

// ELF error
type ElfError struct {
	Err error // TODO: ElfError from elf::ElfError
}

func (e *ElfError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("elf error: %s", e.Err.Error())
	}
	return "elf error"
}

func (e *ElfError) isEbpfError() {}
func (e *ElfError) ErrorKindIndex() int {
	return 1
}

// / Syscall was already registered before
type SyscallAlreadyRegistered struct {
	Instruction uint64
}

func (e *SyscallAlreadyRegistered) Error() string {
	return fmt.Sprintf("syscall %d was already registered before", e.Instruction)
}

func (e *SyscallAlreadyRegistered) isEbpfError() {}
func (e *SyscallAlreadyRegistered) ErrorKindIndex() int {
	return 2
}

// / Syscall was not registered before bind
type SyscallNotRegistered struct {
	Instruction uint64
}

func (e *SyscallNotRegistered) Error() string {
	return fmt.Sprintf("syscall %d was not registered before bind", e.Instruction)
}

func (e *SyscallNotRegistered) isEbpfError() {}
func (e *SyscallNotRegistered) ErrorKindIndex() int {
	return 3
}

// / Syscall already has a bound context object
type SyscallAlreadyBound struct {
	Instruction uint64
}

func (e *SyscallAlreadyBound) Error() string {
	return fmt.Sprintf("syscall %d already has a bound context object", e.Instruction)
}

func (e *SyscallAlreadyBound) isEbpfError() {}
func (e *SyscallAlreadyBound) ErrorKindIndex() int {
	return 4
}

// / Too many syscalls, increase SyscallRegistry::MAX_SYSCALLS.
type TooManySyscalls struct{}

func (e *TooManySyscalls) Error() string {
	return "too many syscalls"
}

func (e *TooManySyscalls) isEbpfError() {}
func (e *TooManySyscalls) ErrorKindIndex() int {
	return 5
}

// / Exceeded max BPF to BPF call depth
type CallDepthExceeded struct {
	Depth       int
	Instruction uint64
}

func (e *CallDepthExceeded) Error() string {
	return fmt.Sprintf("exceeded max BPF to BPF call depth of %d at instruction %d", e.Depth, e.Instruction)
}

func (e *CallDepthExceeded) isEbpfError() {}
func (e *CallDepthExceeded) ErrorKindIndex() int {
	return 6
}

// / Attempt to exit from root call frame
type ExitRootCallFrame struct{}

func (e *ExitRootCallFrame) Error() string {
	return "attempted to exit root call frame"
}

func (e *ExitRootCallFrame) isEbpfError() {}
func (e *ExitRootCallFrame) ErrorKindIndex() int {
	return 7
}

// / Divide by zero"
type DivideByZero struct {
	Instruction uint64
}

func (e *DivideByZero) Error() string {
	return fmt.Sprintf("divide by zero at instruction %d", e.Instruction)
}

func (e *DivideByZero) isEbpfError() {}
func (e *DivideByZero) ErrorKindIndex() int {
	return 8
}

// / Divide overflow
type DivideOverflow struct {
	Instruction uint64
}

func (e *DivideOverflow) Error() string {
	return fmt.Sprintf("divide overflow at instruction %d", e.Instruction)
}

func (e *DivideOverflow) isEbpfError() {}
func (e *DivideOverflow) ErrorKindIndex() int {
	return 9
}

// / Exceeded max instructions allowed
type ExecutionOverrun struct {
	Instruction uint64
}

func (e *ExecutionOverrun) Error() string {
	// TODO: is this the right error message?
	return fmt.Sprintf("attempted to execute past the end of the text segment at instruction %d", e.Instruction)
}

func (e *ExecutionOverrun) isEbpfError() {}
func (e *ExecutionOverrun) ErrorKindIndex() int {
	return 10
}

// / Attempt to call to an address outside the text segment
type CallOutsideTextSegment struct {
	Instruction uint64
	Address     uint64
}

func (e *CallOutsideTextSegment) Error() string {
	return fmt.Sprintf("callx at instruction %d attempted to call outside of the text segment to addr 0x%x", e.Instruction, e.Address)
}

func (e *CallOutsideTextSegment) isEbpfError() {}
func (e *CallOutsideTextSegment) ErrorKindIndex() int {
	return 11
}

// / Exceeded max instructions allowed
type ExceededMaxInstructions struct {
	Instruction uint64
	Max         uint64
}

func (e *ExceededMaxInstructions) Error() string {
	return fmt.Sprintf("exceeded maximum number of instructions allowed (%d) at instruction #%d", e.Max, e.Instruction)
}

func (e *ExceededMaxInstructions) isEbpfError() {}
func (e *ExceededMaxInstructions) ErrorKindIndex() int {
	return 12
}

// / Program has not been JIT-compiled
type JitNotCompiled struct{}

func (e *JitNotCompiled) Error() string {
	return "program has not been JIT-compiled"
}

func (e *JitNotCompiled) isEbpfError() {}
func (e *JitNotCompiled) ErrorKindIndex() int {
	return 13
}

// / Invalid virtual address
type InvalidVirtualAddress struct {
	Address uint64
}

func (e *InvalidVirtualAddress) Error() string {
	return fmt.Sprintf("invalid virtual address 0x%x", e.Address)
}

func (e *InvalidVirtualAddress) isEbpfError() {}
func (e *InvalidVirtualAddress) ErrorKindIndex() int {
	return 14
}

// / Memory region index or virtual address space is invalid
type InvalidMemoryRegion struct {
	Index uint64
}

func (e *InvalidMemoryRegion) Error() string {
	return fmt.Sprintf("invalid memory region at index %d", e.Index)
}

func (e *InvalidMemoryRegion) isEbpfError() {}
func (e *InvalidMemoryRegion) ErrorKindIndex() int {
	return 15
}

// / Access violation (general)
type AccessViolation struct {
	Intruction uint64
	AccessType AccessType
	Address    uint64
	Size       uint64
	Msg        string
}

func (e *AccessViolation) Error() string {
	return fmt.Sprintf(
		"Access violation in %s section at address %x of size %d by instruction #%v",
		e.Msg,
		e.Address,
		e.Size,
		e.Intruction,
	)
}

func (e *AccessViolation) isEbpfError() {}
func (e *AccessViolation) ErrorKindIndex() int {
	return 16
}

// / Access violation (stack specific)
type StackAccessViolation struct {
	Instruction uint64
	AccessType  AccessType
	Address     uint64
	Size        uint64
	Frame       uint64
}

func (e *StackAccessViolation) Error() string {
	return fmt.Sprintf(
		"Access violation in stack frame %d at address %x of size %d by instruction #%d",
		e.Frame,
		e.Address,
		e.Size,
		e.Instruction,
	)
}

func (e *StackAccessViolation) isEbpfError() {}
func (e *StackAccessViolation) ErrorKindIndex() int {
	return 17
}

// / Invalid instruction
type InvalidInstruction struct {
	Instruction uint64
}

func (e *InvalidInstruction) Error() string {
	return fmt.Sprintf("invalid instruction at #%d", e.Instruction)
}

func (e *InvalidInstruction) isEbpfError() {}
func (e *InvalidInstruction) ErrorKindIndex() int {
	return 18
}

// / Unsupported instruction
type UnsupportedInstruction struct {
	Instruction uint64
}

func (e *UnsupportedInstruction) Error() string {
	return fmt.Sprintf("unsupported instruction at instruction #%d", e.Instruction)
}

func (e *UnsupportedInstruction) isEbpfError() {}
func (e *UnsupportedInstruction) ErrorKindIndex() int {
	return 19
}

// / Compilation is too big to fit
type ExhaustedTextSegment struct {
	Instruction uint64
}

func (e *ExhaustedTextSegment) Error() string {
	return fmt.Sprintf("compilation exhausted text segment at instruction #%d", e.Instruction)
}

func (e *ExhaustedTextSegment) isEbpfError() {}
func (e *ExhaustedTextSegment) ErrorKindIndex() int {
	return 20
}

// / Libc function call returned an error
type LibcInvocationFailed struct {
	Msg      string
	Messages []string
	Code     int
}

func (e *LibcInvocationFailed) Error() string {
	return fmt.Sprintf(
		"Libc calling %s %v returned error code %d",
		e.Msg,
		e.Messages,
		e.Code,
	)
}

func (e *LibcInvocationFailed) isEbpfError() {}
func (e *LibcInvocationFailed) ErrorKindIndex() int {
	return 21
}

// / ELF error
type VerifierError struct {
	Err error // TODO: VerifierError from verifier::VerifierError
}

func (e *VerifierError) Error() string {
	return fmt.Sprintf("Verifier error: %v", e.Err)
}

func (e *VerifierError) isEbpfError() {}
func (e *VerifierError) ErrorKindIndex() int {
	return 22
}
