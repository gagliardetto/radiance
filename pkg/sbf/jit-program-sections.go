package sbf

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type JitProgramSections struct {
	// OS page size in bytes and the alignment of the sections
	PageSize uint64
	// A `*const u8` pointer into the text_section for each BPF instruction
	PcSection *buffer
	// The x86 machinecode
	TextSection *buffer
}

// TODO: macro_rules! libc_error_guard

func roundToPageSize(value uint64, pageSize uint64) uint64 {
	return (value + pageSize - 1) / pageSize * pageSize
}

const (
	ANON_PRIVATE = unix.MAP_ANON | unix.MAP_PRIVATE

	READ_WRITE = unix.PROT_READ | unix.PROT_WRITE
	READ_EXEC  = unix.PROT_READ | unix.PROT_EXEC
)

func NewJitProgramSections(pc int, codeSize uint64) (*JitProgramSections, error) {
	if runtime.GOOS == "windows" {
		panic("not implemented")
	}

	pageSize := uint64(os.Getpagesize())

	pcLocTableSize := roundToPageSize(uint64(pc*8), pageSize)
	overAllocatedCodeSize := roundToPageSize(codeSize, pageSize)

	// TODO: what file descriptor to use? -1 for automatic?
	mem, err := unix.Mmap(-1, 0, int(pcLocTableSize+overAllocatedCodeSize), ANON_PRIVATE, READ_WRITE)
	if err != nil {
		return nil, fmt.Errorf("sys/unix.Mmap failed: %v", err)
	}

	pcSectionBuf := newBuffer(mem[:pcLocTableSize])
	textSectionBuf := newBuffer(mem[pcLocTableSize:]) // TODO: newBuffer(mem[pcLocTableSize:pcLocTableSize+overAllocatedCodeSize])?

	return &JitProgramSections{
		PageSize:    pageSize,
		PcSection:   pcSectionBuf,
		TextSection: textSectionBuf,
	}, nil
}

func (e *JitProgramSections) Seal(textSectionUsage uint64) error {
	if e.PageSize > 0 {
		pcLocTableSize := roundToPageSize(uint64(e.PcSection.Len()), u64(e.PageSize))
		overAllocatedCodeSize := roundToPageSize(uint64(e.TextSection.Len()), u64(e.PageSize))
		codeSize := roundToPageSize(u64(textSectionUsage), u64(e.PageSize))
		if runtime.GOOS != "windows" {
			if overAllocatedCodeSize > codeSize {
				err := unix.Munmap(e.TextSection.b[codeSize:]) // TODO: add custom method?
				if err != nil {
					return fmt.Errorf("sys/unix.Munmap failed: %v", err)
				}
			}

			start := pcLocTableSize + u64(textSectionUsage)
			count := codeSize - textSectionUsage
			// write 0xcc (int3) to the unused part of the text section
			for i := uint64(0); i < count; i++ {
				e.TextSection.b[start+i] = 0xcc // Fill with debugger traps
			}
			e.TextSection.b = e.TextSection.b[pcLocTableSize : pcLocTableSize+codeSize]

			{
				err := unix.Mprotect(e.PcSection.b, unix.PROT_READ)
				if err != nil {
					return fmt.Errorf("sys/unix.Mprotect failed: %v", err)
				}
			}
			{
				err := unix.Mprotect(e.TextSection.b, READ_EXEC)
				if err != nil {
					return fmt.Errorf("sys/unix.Mprotect failed: %v", err)
				}
			}
		}
	}
	return nil
}

func (e *JitProgramSections) MemSize() uint64 {
	pcLocTableSize := roundToPageSize(uint64(e.PcSection.Len()), u64(e.PageSize))
	codeSize := roundToPageSize(uint64(e.TextSection.Len()), u64(e.PageSize))
	return pcLocTableSize + codeSize
}

func (e *JitProgramSections) Drop() error {
	pcLocTableSize := roundToPageSize(uint64(e.PcSection.Len()), u64(e.PageSize))
	codeSize := roundToPageSize(uint64(e.TextSection.Len()), u64(e.PageSize))
	if pcLocTableSize+codeSize > 0 {
		// TODO: is the unmapping valid even if separately?
		err := unix.Munmap(e.PcSection.b)
		if err != nil {
			return fmt.Errorf("sys/unix.Munmap failed: %v", err)
		}
		err = unix.Munmap(e.TextSection.b)
		if err != nil {
			return fmt.Errorf("sys/unix.Munmap failed: %v", err)
		}
		e.PcSection = nil
		e.TextSection = nil
		e.PageSize = 0
	}
	return nil
}
