package sbf

import (
	"fmt"
	"math/bits"
	"unsafe"
)

type (
	// type alias
	u8  = uint8
	u16 = uint16
	u32 = uint32
	u64 = uint64

	i8  = int8
	i16 = int16
	i32 = int32
	i64 = int64

	size  = int64
	usize = uint64
)

type (
	u8_  u8
	u16_ u16
	u32_ u32
	u64_ u64

	i8_  i8
	i16_ i16
	i32_ i32
	i64_ i64

	size_  size
	usize_ usize
)

// u8 saturating_add
func (a u8_) saturating_add(b u8_) u8_ {
	if a > 255-b {
		return 255
	}
	return a + b
}

func (a u8_) saturating_sub(b u8_) u8_ {
	if a < b {
		return 0
	}
	return a - b
}

// u8 saturating_mul
func (a u8_) saturating_mul(b u8_) u8_ {
	if a == 0 || b == 0 {
		return 0
	}
	if a > 255/b {
		return 255
	}
	return a * b
}

func (a u8_) saturating_div(b u8_) u8_ {
	if b == 0 {
		return 0
	}
	return a / b
}

func (a u8_) saturating_rem(b u8_) u8_ {
	if b == 0 {
		return 0
	}
	return a % b
}

func (a u8_) checked_shl(b u8_) u8_ {
	if b > 7 {
		return 0
	}
	return a << b
}

// Returns the number of leading zeros in the binary representation of self
func (a u8_) leading_zeros() u8_ {
	return u8_(bits.LeadingZeros8(uint8(a)))
}

func (a u8_) u8() u8 {
	return u8(a)
}

////

// u8 saturating_sub
func (a u16_) saturating_sub(b u16_) u16_ {
	if a < b {
		return 0
	}
	return a - b
}

// u8 saturating_add
func (a u16_) saturating_add(b u16_) u16_ {
	if a > 65535-b {
		return 65535
	}
	return a + b
}

// u8 saturating_mul
func (a u16_) saturating_mul(b u16_) u16_ {
	if a == 0 || b == 0 {
		return 0
	}
	if a > 65535/b {
		return 65535
	}
	return a * b
}

// Checked shift left. Computes self << rhs, returning None if rhs is larger than or equal to the number of bits in self.
func (a u64_) u64() u64 {
	return u64(a)
}

func (a u64_) checked_shl(b u32) u64_ {
	if b >= 64 {
		return 0
	}
	return a << b
}

func (a u64_) saturating_add(b u64) u64 {
	return a.u64() + b
}

func (a u64_) saturating_sub(b u64_) u64_ {
	if a < b {
		return 0
	}
	return a - b
}

func (a u64_) trailing_zeros() u64 {
	return u64(bits.TrailingZeros64(uint64(a)))
}

func (a u64_) saturating_mul(b u64_) u64_ {
	if a == 0 || b == 0 {
		return 0
	}
	return a * b
}

func (a i64_) i64() i64 {
	return i64(a)
}

func (a i64_) u64() u64 {
	return u64(a)
}

func (a i64_) checked_shl(b u32) i64_ {
	if b >= 64 {
		return 0
	}
	return a << b
}

func assert(cond bool, msg string, args ...any) {
	if !cond {
		panic(fmt.Sprintf("assertion failed: "+msg, args...))
	}
}

func debug_assert(cond bool, msg string, args ...any) {
	if !cond {
		panic(fmt.Sprintf("assertion failed: "+msg, args...))
	}
}

func debug_assert_eq(a, b any, msg string, args ...any) {
	if a != b {
		panic(fmt.Sprintf("assertion failed: "+msg, args...))
	}
}

func debug_assert_ne(a, b any, msg string, args ...any) {
	if a == b {
		panic(fmt.Sprintf("assertion failed: "+msg, args...))
	}
}

func matches(a, b any) bool {
	return a == b
}

func boolAsU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func rotate_right(x, k uint64) uint64 {
	return x>>k | x<<(64-k)
}

// TODO: is this correct? Can it be converted back to a unsafe.Pointer?
func fromUnsafePointerToUint64(p unsafe.Pointer) uint64 {
	return u64(uintptr(p))
}
