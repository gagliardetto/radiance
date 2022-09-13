package sbf

import (
	"testing"

	_assert "github.com/stretchr/testify/assert"
)

func TestVars(t *testing.T) {
	_assert.Equal(t, uint8(0), RAX)
	_assert.Equal(t, uint8(1), RCX)
	_assert.Equal(t, uint8(2), RDX)
	_assert.Equal(t, uint8(3), RBX)
	_assert.Equal(t, uint8(4), RSP)
	_assert.Equal(t, uint8(5), RBP)
	_assert.Equal(t, uint8(6), RSI)
	_assert.Equal(t, uint8(7), RDI)
	_assert.Equal(t, uint8(8), R8)
	_assert.Equal(t, uint8(9), R9)
	_assert.Equal(t, uint8(10), R10)
	_assert.Equal(t, uint8(11), R11)
	_assert.Equal(t, uint8(12), R12)
	_assert.Equal(t, uint8(13), R13)
	_assert.Equal(t, uint8(14), R14)
	_assert.Equal(t, uint8(15), R15)
}
