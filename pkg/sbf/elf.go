package sbf

type Executable struct {
	// TODO: implement
	// config          Config
	// elfBytes        *AlignedMemory
	// roSection       Section
	// textSectionInfo SectionInfo
	// bpfFunctions    btree.BTree
	// syscallSymbols  btree.BTree
	syscallRegistry *SyscallRegistry
	// compiledProgram JitProgram
}

// /// Get a symbol's instruction offset
// pub fn lookup_bpf_function(&self, hash: u32) -> Option<usize> {
//     self.bpf_functions.get(&hash).map(|(pc, _name)| *pc)
// }

func (executable *Executable) LookupBPFFunction(hash u32) (pc uint64, ok bool) {
	panic("not implemented")
}
