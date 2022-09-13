package sbf

const (
	// SBF version flag
	EF_SBF_V2 = 0x20
	// Maximum number of instructions in an eBPF program.
	PROG_MAX_INSNS = 65_536
	// Size of an eBPF instructions, in bytes.
	INSN_SIZE = 8
	// Frame pointer register
	FRAME_PTR_REG = 10
	// Stack pointer register
	STACK_PTR_REG = 11
	// First scratch register
	FIRST_SCRATCH_REG = 6
	// Number of scratch registers
	SCRATCH_REGS = 4
	// ELF dump instruction offset
	// Instruction numbers typically start at 29 in the ELF dump, use this offset
	// when reporting so that trace aligns with the dump.
	ELF_INSN_DUMP_OFFSET = 29
	// Alignment of the memory regions in host address space in bytes
	HOST_ALIGN = 16
	// Upper half of a pointer is the region index, lower half the virtual address inside that region.
	VIRTUAL_ADDRESS_BITS = 32
)

const (
	// 	Memory map regions virtual addresses need to be (1 << VIRTUAL_ADDRESS_BITS) bytes apart.
	// Also the region at index 0 should be skipped to catch NULL ptr accesses.

	// Start of the program bits (text and ro segments) in the memory map
	MM_PROGRAM_START = 0x100000000
	// Start of the stack in the memory map
	MM_STACK_START = 0x200000000
	// Start of the heap in the memory map
	MM_HEAP_START = 0x300000000
	// Start of the input buffers in the memory map
	MM_INPUT_START = 0x400000000
)
