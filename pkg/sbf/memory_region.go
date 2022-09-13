package sbf

import (
	"unsafe"
)

type AccessType uint8

const (
	// Read
	AccessTypeLoad AccessType = iota
	// Write
	AccessTypeStore
)

type MemoryRegion struct {
	// start host address
	HostAddr uint64
	// start virtual address
	VmAddr uint64
	// Length in bytes
	Len uint64
	// Size of regular gaps as bit shift (63 means this region is continuous)
	VmGapShift uint8
	// Is also writable (otherwise it is readonly)
	IsWritable bool
}

// are these values correct?
const (
	HOST_ADDR_OFFSET    i32 = 0
	VM_ADDR_OFFSET      i32 = HOST_ADDR_OFFSET + i32(unsafe.Sizeof(uint64(0)))
	LEN_OFFSET          i32 = VM_ADDR_OFFSET + i32(unsafe.Sizeof(uint64(0)))
	VM_GAP_SHIFT_OFFSET i32 = LEN_OFFSET + i32(unsafe.Sizeof(uint64(0)))
	IS_WRITABLE_OFFSET  i32 = VM_GAP_SHIFT_OFFSET + i32(unsafe.Sizeof(uint8(0)))
)

// func newMemoryRegion(slice []byte, vmAddr uint64, vmGapSize uint64, isWritable bool) *MemoryRegion {
// 	var vmGapShift u8_ = u8_(sizeof(u64(0))).
// 		saturating_mul(8).
// 		saturating_sub(1)
// 	if vmGapSize > 0 {
// 		vmGapShift = vmGapShift.saturating_sub(u8_(vmGapSize).leading_zeros())
// 		debug_assert_eq(u64_(vmGapSize), u64_(1).checked_shl(u32(vmGapShift)), "")
// 	}
// 	return &MemoryRegion{
// 		HostAddr:   u64(slice.uintptr()),
// 		VmAddr:     vmAddr,
// 		Len:        uint64(slice.Len()),
// 		VmGapShift: vmGapShift.u8(),
// 		IsWritable: isWritable,
// 	}
// }

// // Only to be used in tests and benches
// func NewForTesting(slice []byte, vmAddr uint64, vmGapSize uint64, isWritable bool) *MemoryRegion {
// 	return newMemoryRegion(slice, vmAddr, vmGapSize, isWritable)
// }

// // Creates a new readonly MemoryRegion from a slice
// func NewReadonly(slice []byte, vmAddr uint64) *MemoryRegion {
// 	return newMemoryRegion(slice, vmAddr, 0, false)
// }

// // Creates a new writable MemoryRegion from a mutable slice
// func NewWritable(slice []byte, vmAddr uint64) *MemoryRegion {
// 	return newMemoryRegion(slice, vmAddr, 0, true)
// }

// // Creates a new writable gapped MemoryRegion from a mutable slice
// func NewWritableGapped(slice []byte, vm_addr uint64, vm_gap_size uint64) *MemoryRegion {
// 	return newMemoryRegion(slice, vm_addr, vm_gap_size, true)
// }

// // Convert a virtual machine address into a host address
// func (mr *MemoryRegion) VmToHost(vmAddr u64_, len uint64) (uint64, EbpfError) {
// 	// This can happen if a region starts at an offset from the base region
// 	// address, eg with rodata regions if config.optimize_rodata = true, see
// 	// Elf::get_ro_region.
// 	if vmAddr.u64() < mr.VmAddr {
// 		return 0, &InvalidVirtualAddress{vmAddr.u64()}
// 	}

// 	// TODO: check for overflow
// 	beginOffset := vmAddr.saturating_sub(u64_(mr.VmAddr))
// 	isInGap := (beginOffset.checked_shl(u32(mr.VmGapShift)))&1 == 1
// 	gapMask := i64_(-1).checked_shl(u32(mr.VmGapShift)).u64()
// 	gappedOffset := (beginOffset.u64()&gapMask)>>1 | (beginOffset.u64() & ^gapMask)
// 	if endOffset := gappedOffset + len; endOffset <= mr.Len && !isInGap {
// 		// TODO: is the operation right?
// 		return u64_(mr.HostAddr).saturating_add(gappedOffset), nil
// 	}
// 	return 0, &InvalidVirtualAddress{vmAddr.u64()}
// }

// func (mr MemoryRegion) String() string {
// 	return fmt.Sprintf(
// 		"host_addr: %x-%x, vm_addr: %x-%x, len: %d",
// 		mr.HostAddr,
// 		u64_(mr.HostAddr).saturating_add(mr.Len),
// 		mr.VmAddr,
// 		u64_(mr.VmAddr).saturating_add(mr.Len),
// 		mr.Len,
// 	)
// }

// func (mr MemoryRegion) Compare(other MemoryRegion) int {
// 	if mr.VmAddr == other.VmAddr {
// 		return 0
// 	}
// 	if mr.VmAddr < other.VmAddr {
// 		return -1
// 	}
// 	return 1
// }

// func (mr MemoryRegion) Less(other MemoryRegion) bool {
// 	return mr.VmAddr < other.VmAddr
// }

// func (mr MemoryRegion) Equal(other MemoryRegion) bool {
// 	return mr.VmAddr == other.VmAddr
// }

// type MemoryMapping struct {
// 	regions []*MemoryRegion
// 	config  *Config
// }

// func NewMemoryMapping(regions []*MemoryRegion, config *Config) (*MemoryMapping, error) {
// 	sort.Slice(regions, func(i, j int) bool {
// 		return regions[i].VmAddr < regions[j].VmAddr
// 	})
// 	for index, region := range regions {
// 		// TODO: checked_shr
// 		if region.VmAddr>>VIRTUAL_ADDRESS_BITS != uint64(index) {
// 			return nil, &InvalidMemoryRegion{u64(index)}
// 		}
// 	}
// 	return &MemoryMapping{regions, config}, nil
// }

// // Given a list of regions translate from virtual machine to host address
// func (m *MemoryMapping) Map(accessType AccessType, vm_addr uint64, length uint64) (uint64, error) {
// 	index := vm_addr >> VIRTUAL_ADDRESS_BITS
// 	if index >= uint64(len(m.regions)) {
// 		return 0, &InvalidMemoryRegion{index}
// 	}
// 	region := m.regions[index]
// 	if accessType == AccessTypeLoad || region.IsWritable {
// 		if host_addr, err := region.VmToHost(u64_(vm_addr), length); err == nil {
// 			return host_addr, nil
// 		}
// 	}
// 	return m.GenerateAccessViolation(accessType, vm_addr, length)
// }

// // Helper for map to generate errors
// func (m *MemoryMapping) GenerateAccessViolation(accessType AccessType, vm_addr uint64, len uint64) (uint64, error) {
// 	stack_frame := (vm_addr - MM_STACK_START) / uint64(m.config.StackFrameSize)
// 	if !m.config.DynamicStackFrames && stack_frame >= 0 && stack_frame <= uint64(m.config.MaxCallDepth)+1 {
// 		return 0, &StackAccessViolation{
// 			0, // Filled out later
// 			accessType,
// 			vm_addr,
// 			len,
// 			stack_frame,
// 		}
// 	} else {
// 		region_name := "unknown"
// 		// TODO: is this correct?
// 		if vm_addr&^MM_PROGRAM_START == MM_PROGRAM_START {
// 			region_name = "program"
// 		} else if vm_addr&^MM_STACK_START == MM_STACK_START {
// 			region_name = "stack"
// 		} else if vm_addr&^MM_HEAP_START == MM_HEAP_START {
// 			region_name = "heap"
// 		} else if vm_addr&^MM_INPUT_START == MM_INPUT_START {
// 			region_name = "input"
// 		}
// 		return 0, &AccessViolation{
// 			0, // Filled out later
// 			accessType,
// 			vm_addr,
// 			len,
// 			region_name,
// 		}
// 	}
// }

// // Returns the `MemoryRegion`s in this mapping
// func (m *MemoryMapping) GetRegions() []*MemoryRegion {
// 	return m.regions
// }

// // Replaces the `MemoryRegion` at the given index
// func (m *MemoryMapping) ReplaceRegion(index u64, region *MemoryRegion) error {
// 	if int(index) >= len(m.regions) {
// 		return &InvalidMemoryRegion{u64(index)}
// 	}
// 	beginIndex := u64(region.VmAddr >> VIRTUAL_ADDRESS_BITS)
// 	endIndex := (region.VmAddr + region.Len - 1) >> VIRTUAL_ADDRESS_BITS
// 	if beginIndex != index || endIndex != index {
// 		return &InvalidMemoryRegion{index}
// 	}
// 	m.regions[index] = region
// 	return nil
// }
