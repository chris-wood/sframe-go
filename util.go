package sframe

import "encoding/binary"

func numBytes(x uint64) int {
	count := 0
	for {
		if x > 0 {
			x >>= 1
			count++
		} else {
			break
		}
	}
	return (count + 7) / 8
}

func encodeBigEndian(x uint64, n int) []byte {
	if n == 8 {
		buffer := make([]byte, 8)
		binary.BigEndian.PutUint64(buffer, uint64(x))
		return buffer
	} else if n == 2 {
		buffer := make([]byte, 2)
		binary.BigEndian.PutUint16(buffer, uint16(x))
		return buffer
	} else if n > 8 {
		// XXX(caw): this doesn't handle counters larger than 2^64
		buffer := make([]byte, 8)
		binary.BigEndian.PutUint64(buffer, uint64(x))
		zeroes := make([]byte, n-8)
		return append(zeroes, buffer...)
	} else {
		panic("unsupported (lazy programmer)")
	}
}
