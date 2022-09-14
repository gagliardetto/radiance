package sbf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIns(t *testing.T) {
	{
		/// let prog: &[u8] = &[
		///     0xb7, 0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78,
		///     ];
		/// let insn = ebpf::Insn {
		///     ptr: 0x00,
		///     opc: 0xb7,
		///     dst: 2,
		///     src: 1,
		///     off: 0x3456,
		///     imm: 0x789abcde
		/// };
		/// assert_eq!(insn.to_array(), prog);

		prog := [INSN_SIZE]uint8{0xb7, 0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78}

		insn := Insn{
			Ptr: 0x00,
			Opc: 0xb7,
			Dst: 2,
			Src: 1,
			Off: 0x3456,
			Imm: 0x789abcde,
		}

		require.Equal(t, prog, insn.to_array())
	}
}
func TestCallImmediate(t *testing.T) {
	program := NewBpfCode()
	program.Call().SetImm(0x11_22_33_44).Push()

	require.Equal(t, program.Bytes(), []byte{0x85, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11})
}
func TestExitOperation(t *testing.T) {
	program := NewBpfCode()
	program.Exit().Push()

	require.Equal(t, []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstEqualsSrc(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondEquals, SourceReg).SetDst(0x01).SetSrc(0x02).Push()

	require.Equal(t, []byte{0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstGreaterThanSrc(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondGreater, SourceReg).
		SetDst(0x03).
		SetSrc(0x02).
		Push()

	require.Equal(t, program.Bytes(), []byte{0x2d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestJumpOnDstGreaterOrEqualsToSrc(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondGreaterEquals, SourceReg).SetDst(0x04).SetSrc(0x01).Push()

	require.Equal(t, program.Bytes(), []byte{0x3d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestJumpOnDstLowerThanSrc(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLower, SourceReg).SetDst(0x03).SetSrc(0x02).Push()
	require.Equal(t, []byte{0xad, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstLowerOrEqualsToSrc(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLowerEquals, SourceReg).
		SetDst(0x04).
		SetSrc(0x01).
		Push()

	require.Equal(t, []byte{
		0xbd, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestJumpOnDstBitAndWithSrcNotEqualZero(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondBitAnd, SourceReg).SetDst(0x05).SetSrc(0x02).Push()

	require.Equal(t, []byte{
		0x4d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestJumpOnDstNotEqualsSrc(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondNotEquals, SourceReg).
		SetDst(0x03).
		SetSrc(0x05).
		Push()

	require.Equal(t, []byte{0x5d, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstGreaterThanSrcSigned(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondGreaterSigned, SourceReg).
		SetDst(0x04).
		SetSrc(0x01).
		Push()

	require.Equal(t, program.Bytes(), []byte{0x6d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestJumpOnDstGreaterOrEqualsSrcSigned(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondGreaterEqualsSigned, SourceReg).SetDst(0x01).SetSrc(0x03).Push()

	require.Equal(t, []byte{0x7d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstLowerThanSrcSigned(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLowerSigned, SourceReg).
		SetDst(0x04).
		SetSrc(0x01).
		Push()

	require.Equal(t, []byte{0xcd, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstLowerOrEqualsSrcSigned(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondLowerEqualsSigned, SourceReg).
		SetDst(0x01).
		SetSrc(0x03).
		Push()

	require.Equal(t, []byte{
		0xdd, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestJumpToLabel(t *testing.T) {
	program := NewBpfCode()
	program.JumpUnconditional().SetOff(0x00_11).Push()

	require.Equal(t, program.Bytes(), []byte{0x05, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestJumpOnDstEqualsConst(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondEquals, SourceImm).
		SetDst(0x01).
		SetImm(0x00_11_22_33).
		Push()

	require.Equal(t, program.Bytes(), []byte{0x15, 0x01, 0x00, 0x00, 0x33, 0x22, 0x11, 0x00})
}
func TestJumpOnDstGreaterThanConst(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondGreater, SourceImm).
		SetDst(0x02).
		SetImm(0x00110011).
		Push()

	require.Equal(t, []byte{
		0x25, 0x02, 0x00, 0x00, 0x11, 0x00, 0x11, 0x00,
	}, program.Bytes())
}
func TestJumpOnDstGreaterOrEqualsToConst(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondGreaterEquals, SourceImm).
		SetDst(0x04).
		SetImm(0x00_22_11_00).
		Push()

	require.Equal(
		t,
		[]byte{0x35, 0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00},
		program.Bytes(),
	)
}
func TestJumpOnDstLowerThanConst(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLower, SourceImm).SetDst(0x02).SetImm(0x00_11_00_11).Push()

	require.Equal(t, []byte{0xa5, 0x02, 0x00, 0x00, 0x11, 0x00, 0x11, 0x00}, program.Bytes())
}
func TestJumpOnDstLowerOrEqualsToConst(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLowerEquals, SourceImm).SetDst(0x04).SetImm(0x00_22_11_00).Push()

	require.Equal(t, []byte{0xb5, 0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00}, program.Bytes())
}
func Test_jump_on_dst_bit_and_with_const_not_equal_zero(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondBitAnd, SourceImm).
		SetDst(0x05).
		Push()

	require.Equal(t, []byte{0x45, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstNotEqualsConst(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondNotEquals, SourceImm).
		SetDst(0x03).
		Push()

	require.Equal(t, []byte{0x55, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstGreaterThanConstSigned(t *testing.T) {
	var program BpfCode
	program.JumpConditional(CondGreaterSigned, SourceImm).SetDst(0x04).Push()

	require.Equal(
		t,
		[]byte{0x65, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		program.Bytes(),
	)
}
func TestJumpOnDstGreaterOrEqualsSrcSigned2(t *testing.T) {
	program := NewBpfCode()
	program.
		JumpConditional(CondGreaterEqualsSigned, SourceImm).
		SetDst(0x01).
		Push()

	require.Equal(t, []byte{0x75, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestJumpOnDstLowerThanConstSigned(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLowerSigned, SourceImm).SetDst(0x04).Push()

	require.Equal(t, []byte{
		0xc5, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestJumpOnDstLowerOrEqualsSrcSigned2(t *testing.T) {
	program := NewBpfCode()
	program.JumpConditional(CondLowerEqualsSigned, SourceImm).SetDst(0x01).Push()

	require.Equal(t, []byte{0xd5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestStoreWordFromDstIntoImmediateAddress(t *testing.T) {
	program := NewBpfCode()
	program.Store(MemSizeWord).SetDst(0x01).SetOff(0x0011).SetImm(0x11223344).Push()

	expected := []byte{0x62, 0x01, 0x11, 0x00, 0x44, 0x33, 0x22, 0x11}
	require.Equal(t, expected, program.Bytes())
}
func TestStoreHalfWordFromDstIntoImmediateAddress(t *testing.T) {
	program := NewBpfCode()
	program.
		Store(MemSizeHalfWord).SetDst(0x02).SetOff(0x11_22).Push()

	require.Equal(t, []byte{0x6a, 0x02, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestStoreByteFromDstIntoImmediateAddress(t *testing.T) {
	program := BpfCode{}
	program.Store(MemSizeByte).Push()

	require.Equal(t, program.Bytes(), []byte{0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestStoreDoubleWordFromDstIntoImmediateAddress(t *testing.T) {
	program := NewBpfCode()
	program.Store(MemSizeDoubleWord).Push()

	require.Equal(t, []byte{
		0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestStoreWordFromDstIntoSrcAddress(t *testing.T) {
	program := NewBpfCode()
	program.
		StoreX(MemSizeWord).
		SetDst(0x01).
		SetSrc(0x02).
		Push()

	require.Equal(t, []byte{0x63, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestStoreHalfWordFromDstIntoSrcAddress(t *testing.T) {
	program := NewBpfCode()
	program.StoreX(MemSizeHalfWord).Push()

	require.Equal(t, []byte{
		0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestStoreByteFromDstIntoSrcAddress(t *testing.T) {
	program := NewBpfCode()
	program.StoreX(MemSizeByte).Push()

	require.Equal(t, []byte{0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestStoreDoubleWordFromDstIntoSrcAddress(t *testing.T) { // line 1103
	program := NewBpfCode()
	program.StoreX(MemSizeDoubleWord).Push()

	require.Equal(t, program.Bytes(), []byte{0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestLoadWordFromSetSrcWithOffset(t *testing.T) {
	program := NewBpfCode()
	program.
		LoadX(MemSizeWord).
		SetDst(0x01).
		SetSrc(0x02).
		SetOff(0x00_02).
		Push()

	require.Equal(t, []byte{0x61, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadHalfWordFromSetSrcWithOffset(t *testing.T) {
	program := NewBpfCode()
	program.LoadX(MemSizeHalfWord).SetDst(0x02).SetSrc(0x01).SetOff(0x1122).Push()

	require.Equal(t, []byte{0x69, 0x12, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadByteFromSetSrcWithOffset(t *testing.T) {
	program := NewBpfCode()
	program.LoadX(MemSizeByte).SetDst(0x01).SetSrc(0x04).SetOff(0x00_11).Push()

	require.Equal(t, []byte{0x71, 0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadDoubleWordFromSetSrcWithOffset(t *testing.T) {
	program := NewBpfCode()
	program.LoadX(MemSizeDoubleWord).SetDst(0x04).SetSrc(0x05).SetOff(0x4455).Push()
	require.Equal(t, []byte{0x79, 0x54, 0x55, 0x44, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadDoubleWord(t *testing.T) {
	program := NewBpfCode()
	program.
		Load(MemSizeDoubleWord).
		SetDst(0x01).
		SetImm(0x00_01_02_03).
		Push()

	require.Equal(t, program.Bytes(), []byte{0x18, 0x01, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00})
}
func TestLoadAbsWord(t *testing.T) {
	program := NewBpfCode()
	program.LoadAbs(MemSizeWord).Push()

	require.Equal(t, []byte{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadAbsHalfWord(t *testing.T) {
	program := NewBpfCode()
	program.LoadAbs(MemSizeHalfWord).SetDst(0x05).Push()

	require.Equal(t, []byte{0x28, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadAbsByte(t *testing.T) {
	program := NewBpfCode()
	program.LoadAbs(MemSizeByte).SetDst(0x01).Push()

	require.Equal(t, program.Bytes(), []byte{0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
func TestLoadAbsDoubleWord(t *testing.T) {
	program := NewBpfCode()
	program.LoadAbs(MemSizeDoubleWord).SetDst(0x01).SetImm(0x01_02_03_04).Push()

	require.Equal(t, []byte{0x38, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01}, program.Bytes())
}
func TestLoadIndirectWord(t *testing.T) {
	program := NewBpfCode()
	program.LoadInd(MemSizeWord).Push()

	require.Equal(t, []byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadIndirectHalfWord(t *testing.T) {
	program := NewBpfCode()
	program.LoadInd(MemSizeHalfWord).Push()

	require.Equal(t, []byte{
		0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, program.Bytes())
}
func TestLoadIndirectByte(t *testing.T) {
	program := NewBpfCode()
	program.LoadInd(MemSizeByte).Push()

	require.Equal(t, []byte{0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
func TestLoadIndirectDoubleWord(t *testing.T) { // line 1286
	program := NewBpfCode()
	program.LoadInd(MemSizeDoubleWord).Push()

	require.Equal(t, []byte{0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, program.Bytes())
}
