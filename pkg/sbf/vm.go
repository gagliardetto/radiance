package sbf

import (
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// VM is the virtual machine abstraction, implemented by each executor.
type VM interface {
	VMContext() any

	Read(addr uint64, p []byte) error
	Read8(addr uint64) (uint8, error)
	Read16(addr uint64) (uint16, error)
	Read32(addr uint64) (uint32, error)
	Read64(addr uint64) (uint64, error)

	Write(addr uint64, p []byte) error
	Write8(addr uint64, x uint8) error
	Write16(addr uint64, x uint16) error
	Write32(addr uint64, x uint32) error
	Write64(addr uint64, x uint64) error
}

// VMOpts specifies virtual machine parameters.
type VMOpts struct {
	// Machine parameters
	HeapSize int
	Syscalls SyscallRegistry_
	Tracer   TraceSink

	// Execution parameters
	Context any // passed to syscalls
	MaxCU   int
	Input   []byte // mapped at VaddrInput
}

type Exception struct {
	PC     int64
	Detail error
}

func (e *Exception) Error() string {
	return fmt.Sprintf("exception at %d: %s", e.PC, e.Detail)
}

func (e *Exception) Unwrap() error {
	return e.Detail
}

// Exception codes.
var (
	ExcDivideByZero   = errors.New("division by zero")
	ExcDivideOverflow = errors.New("divide overflow")
	ExcOutOfCU        = errors.New("compute unit overrun")
	ExcCallDepth      = errors.New("call depth exceeded")
)

type ExcBadAccess struct {
	Addr   uint64
	Size   uint32
	Write  bool
	Reason string
}

func NewExcBadAccess(addr uint64, size uint32, write bool, reason string) ExcBadAccess {
	return ExcBadAccess{
		Addr:   addr,
		Size:   size,
		Write:  write,
		Reason: reason,
	}
}

func (e ExcBadAccess) Error() string {
	return fmt.Sprintf("bad memory access at %#x (size=%d write=%v), reason: %s", e.Addr, e.Size, e.Write, e.Reason)
}

type ExcCallDest struct {
	Imm uint32
}

func (e ExcCallDest) Error() string {
	return fmt.Sprintf("unknown symbol or syscall 0x%08x", e.Imm)
}

type Config struct {
	// Maximum call depth
	MaxCallDepth int
	// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
	StackFrameSize int
	// Enables gaps in VM address space between the stack frames
	EnableStackFrameGaps bool
	// Maximal pc distance after which a new instruction meter validation is emitted by the JIT
	InstructionMeterCheckpointDistance int
	// Enable instruction meter and limiting
	EnableInstructionMeter bool
	// Enable instruction tracing
	EnableInstructionTracing bool
	// Enable dynamic string allocation for labels
	EnableSymbolAndSectionLabels bool
	// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
	RejectBrokenElfs bool
	// Ratio of native host instructions per random no-op in JIT (0 = OFF)
	NoopInstructionRate uint64
	// Enable disinfection of immediate values and offsets provided by the user in JIT
	SanitizeUserProvidedValues bool
	// Encrypt the environment registers in JIT
	EncryptEnvironmentRegisters bool
	// Throw ElfError::SymbolHashCollision when a BPF function collides with a registered syscall
	SyscallBpfFunctionHashCollision bool
	// Have the verifier reject "callx r10"
	RejectCallxR10 bool
	// Use dynamic stack frame sizes
	DynamicStackFrames bool
	// Enable native signed division
	EnableSdiv bool
	// Avoid copying read only sections when possible
	OptimizeRodata bool
	// Support syscalls via pseudo calls (insn.src = 0)
	StaticSyscalls bool
	// Allow sh_addr != sh_offset in elf sections. Used in SBFv2 to align
	// section vaddrs to MM_PROGRAM_START.
	EnableElfVaddr bool
	// Use the new ELF parser
	NewElfParser bool
	// Ensure that rodata sections don't exceed their maximum allowed size and
	// overlap with the stack
	RejectRodataStackOverlap bool
}

// Returns the size of the stack memory region
func (conf *Config) StackSize() int {
	return conf.StackFrameSize * conf.MaxCallDepth
}

const MAX_SYSCALLS uint64 = 128

type ProgramResult struct {
	// The return value of the program
	Retval uint64
	Err    EbpfError
}

type ProgramEnvironment struct {
	/// The MemoryMapping describing the address space of the program
	memory_mapping *MemoryMapping
	/// Pointers to the context objects of syscalls
	syscall_context_objects [MAX_SYSCALLS]*u8 // TODO: what type is this?
	/// The instruction tracer
	tracer *Tracer
}

const (
	MEMORY_MAPPING_OFFSET = 0
	SYSCALLS_OFFSET       = MEMORY_MAPPING_OFFSET + unsafe.Sizeof(MemoryMapping{})
	TRACER_OFFSET         = SYSCALLS_OFFSET + unsafe.Sizeof([MAX_SYSCALLS]*u8{}) // TODO: is this correct?
)

type Tracer struct {
	// Contains the state at every instruction in order of execution
	Log []uint64
}

// Logs the state of a single instruction
func (tracer *Tracer) Trace(state [12]uint64) {
	tracer.Log = append(tracer.Log, state[:]...)
}

func (tracer *Tracer) Consume(amount u64) {
	panic("not implemented")
}

func (tracer *Tracer) GetRemaining() u64 {
	panic("not implemented")
}

// Use this method to print the log of this tracer
func (tracer *Tracer) Write(output io.Writer, analysis *Analysis) error {
	panic("not implemented")
}

// Compares an interpreter trace and a JIT trace.
// The log of the JIT can be longer because it only validates the instruction meter at branches.
func (tracer *Tracer) Compare(interpreter *Tracer, jit *Tracer) bool {
	panic("not implemented")
}

type InstructionMeter interface {
	/// Consume instructions
	Consume(amount u64)
	/// Get the number of remaining instructions allowed
	GetRemaining() u64
}

// Syscall function and binding slot for a context object
type Syscall struct {
	// Syscall init
	Init u64
	// Call the syscall function
	Function u64
	// Slot of context object
	ContextObjectSlot u64
}

// Holds the syscall function pointers of an Executable
type SyscallRegistry struct {
	// Function pointers by symbol
	entries map[u32]Syscall
	// Context object slots by function pointer
	context_object_slots map[u64]usize
}

// impl SyscallRegistry {
//     const MAX_SYSCALLS: usize = 128;

// /// Register a syscall function by its symbol hash
// pub fn register_syscall_by_hash<'a, C, E: UserDefinedError, O: SyscallObject<E>>(
//
//	&mut self,
//	hash: u32,
//	init: SyscallInit<'a, C, E>,
//	function: SyscallFunction<E, &mut O>,
//
//	) -> Result<(), EbpfError<E>> {
//	    let init = init as *const u8 as u64;
//	    let function = function as *const u8 as u64;
//	    let context_object_slot = self.entries.len();
//	    if context_object_slot == SyscallRegistry::MAX_SYSCALLS {
//	        return Err(EbpfError::TooManySyscalls);
//	    }
//	    if self
//	        .entries
//	        .insert(
//	            hash,
//	            Syscall {
//	                init,
//	                function,
//	                context_object_slot,
//	            },
//	        )
//	        .is_some()
//	        || self
//	            .context_object_slots
//	            .insert(function, context_object_slot)
//	            .is_some()
//	    {
//	        Err(EbpfError::SyscallAlreadyRegistered(hash as usize))
//	    } else {
//	        Ok(())
//	    }
//	}
func (registry *SyscallRegistry) RegisterSyscallByHash(hash u32, initf SyscallInit, function SyscallFunction) error {
	panic("not implemented")
}

// LookupSyscall
func (registry *SyscallRegistry) LookupSyscall(hash u32) (Syscall, bool) {
	panic("not implemented")
}

// TODO: implement this
type SyscallInit func(*ExecutionContext) error

// TODO: implement this
type ExecutionContext struct {
	// The program environment
	Environment *ProgramEnvironment
	// The instruction meter
	InstructionMeter InstructionMeter
	// The syscall context object
	ContextObject *u8
}

//     /// Register a syscall function by its symbol name
//     pub fn register_syscall_by_name<'a, C, E: UserDefinedError, O: SyscallObject<E>>(
//         &mut self,
//         name: &[u8],
//         init: SyscallInit<'a, C, E>,
//         function: SyscallFunction<E, &mut O>,
//     ) -> Result<(), EbpfError<E>> {
//         self.register_syscall_by_hash::<C, E, O>(ebpf::hash_symbol_name(name), init, function)
//     }

//     /// Get a symbol's function pointer and context object slot
//     pub fn lookup_syscall(&self, hash: u32) -> Option<&Syscall> {
//         self.entries.get(&hash)
//     }

//     /// Get a function pointer's and context object slot
//     pub fn lookup_context_object_slot(&self, function_pointer: u64) -> Option<usize> {
//         self.context_object_slots.get(&function_pointer).copied()
//     }

//     /// Get the number of registered syscalls
//     pub fn get_number_of_syscalls(&self) -> usize {
//         self.entries.len()
//     }

//     /// Calculate memory size
//     pub fn mem_size(&self) -> usize {
//         mem::size_of::<Self>()
//             + self.entries.capacity() * mem::size_of::<(u32, Syscall)>()
//             + self.context_object_slots.capacity() * mem::size_of::<(u64, usize)>()
//     }
// }
