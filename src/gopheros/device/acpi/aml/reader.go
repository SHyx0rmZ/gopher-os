package aml

import "io"

type seekableByteReader struct {
	offset uint32
	data   []byte
}

// EOF returns true if the end of the stream has been reached.
func (r *seekableByteReader) EOF() bool {
	return r.offset == uint32(len(r.data))
}

// ReadByte returns the next byte from the stream.
func (r *seekableByteReader) ReadByte() (byte, error) {
	if r.EOF() {
		return 0, io.EOF
	}

	r.offset++
	return r.data[r.offset-1], nil
}

// PeekByte returns the next byte from the stream without advancing the read pointer.
func (r *seekableByteReader) PeekByte() (byte, error) {
	if r.EOF() {
		return 0, io.EOF
	}

	return r.data[r.offset], nil
}

// LastByte returns the last byte read off the stream
func (r *seekableByteReader) LastByte() (byte, error) {
	if r.offset == 0 {
		return 0, io.EOF
	}

	return r.data[r.offset-1], nil
}

// UnreadByte moves back the read pointer by one byte.
func (r *seekableByteReader) UnreadByte() {
	r.offset--
}

// Offset returns the current offset.
func (r *seekableByteReader) Offset() uint32 {
	return r.offset
}

// SetOffset sets the reader offset to the supplied value.
func (r *seekableByteReader) SetOffset(off uint32) {
	r.offset = off
}
