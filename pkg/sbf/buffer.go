package sbf

import (
	"encoding/binary"
	"fmt"
)

type buffer struct {
	b  []byte
	i  int
	sz int
}

func newBuffer(b []byte) *buffer {
	return &buffer{b, 0, len(b)}
}

func (b *buffer) extend(length int) {
	if len(b.b)-b.i >= length {
		return
	}
	bb := make([]byte, len(b.b)*2)
	copy(bb, b.b[:b.i])
	b.b = bb
}

func (b *buffer) Len() int    { return b.i }
func (b *buffer) Cap() int    { return len(b.b) }
func (b *buffer) Get() []byte { return b.b[:b.i] }
func (b *buffer) Reset()      { b.ResizeReset(b.sz) }
func (b *buffer) ResizeReset(capacity int) {
	if len(b.b) != capacity {
		b.b = make([]byte, capacity)
	}
	b.i = 0
}

func (b *buffer) Byte(v byte) {
	b.extend(1)
	b.b[b.i] = v
	b.i++
}

func (b *buffer) Byte2(v1, v2 byte) {
	b.extend(2)
	b.b[b.i], b.b[b.i+1] = v1, v2
	b.i += 2
}

func (b *buffer) Bytes(v []byte) {
	b.extend(len(v))
	copy(b.b[b.i:], v)
	b.i += len(v)
}

func (b *buffer) Uint8(v uint8) {
	b.extend(1)
	b.Byte(byte(v))
}

func (b *buffer) Uint16(v uint16) {
	b.extend(2)
	binary.LittleEndian.PutUint16(b.b[b.i:], v)
	b.i += 2
}

func (b *buffer) Uint32(v uint32) {
	b.extend(4)
	binary.LittleEndian.PutUint32(b.b[b.i:], v)
	b.i += 4
}

func (b *buffer) Uint64(v uint64) {
	b.extend(8)
	binary.LittleEndian.PutUint64(b.b[b.i:], v)
	b.i += 8
}

func (b *buffer) Nop(length uint8) {
	maxNop := uint8(len(nops))
	for length > 0 {
		if length > maxNop {
			b.Bytes(nops[maxNop-1][:maxNop])
			length -= maxNop
		} else {
			b.Bytes(nops[length-1][:length])
			break
		}
	}
}

func uint64SliceSetByIndex(slice []byte, index uint64, val uint64) {
	start := index * 8
	end := start + 8
	binary.LittleEndian.PutUint64(slice[start:end], val)
}

func uint64SliceGetByIndex(slice []byte, index uint64) uint64 {
	start := index * 8
	end := start + 8
	return binary.LittleEndian.Uint64(slice[start:end])
}
func (b *buffer) CanFit(offset uint64, lenght int) bool {
	// return true if the buffer can fit the data at the given offset
	return int(offset)+lenght <= b.Cap()
}

type ErrBufferTooSmall struct {
	Have int
	Want int
}

func (e ErrBufferTooSmall) Error() string {
	return fmt.Sprintf("buffer too small: have %d, want %d", e.Have, e.Want)
}

func (b *buffer) Uint64SliceSetByIndex(index uint64, val uint64) error {
	// check if we can fit the data at the given offset
	if !b.CanFit(index, 8) {
		return &ErrBufferTooSmall{
			Have: b.Cap(),
			Want: int(index) + 8,
		}
	}
	uint64SliceSetByIndex(b.b, index, val)
	return nil
}

func (b *buffer) Uint64SliceGetByIndex(index uint64) uint64 {
	// check if the index is valid
	if !b.CanFit(index, 8) {
		return 0
	}
	return uint64SliceGetByIndex(b.b, index)
}
