package sframe

import "encoding/binary"

func encodeHeader(kid uint64, ctr uint64) []byte {
	kidBuffer := []byte{}
	ctrBuffer := []byte{}
	headerPrefix := byte(0)
	if kid < 8 {
		headerPrefix |= uint8(kid) << 4
	} else {
		kidBytes := numBytes(kid)
		kidBuffer = make([]byte, 8)
		binary.BigEndian.PutUint64(kidBuffer, uint64(kid))
		kidBuffer = kidBuffer[(8 - kidBytes):]
		headerPrefix |= 0x80
		headerPrefix |= (uint8(kidBytes) - 1) << 4
	}
	if ctr < 8 {
		headerPrefix |= uint8(ctr)
	} else {
		ctrBytes := numBytes(ctr)
		ctrBuffer = make([]byte, 8)
		binary.BigEndian.PutUint64(ctrBuffer, uint64(ctr))
		ctrBuffer = ctrBuffer[(8 - ctrBytes):]
		headerPrefix |= 0x08
		headerPrefix |= uint8(ctrBytes) - 1
	}
	header := []byte{headerPrefix}
	header = append(header, kidBuffer...)
	header = append(header, ctrBuffer...)

	return header
}

func decodeHeader(header []byte) (uint64, uint64, int) {
	kid := uint64(0)
	kidLen := 0
	ctr := uint64(0)
	ctrLen := 0
	if header[0]&0x80 == 0 {
		kid = uint64((header[0] & 0x70) >> 4)
	} else {
		kidLen = int((header[0]&0x70)>>4) + 1
		buffer := make([]byte, 8)
		kidBuffer := header[1 : 1+kidLen]
		copy(buffer[8-kidLen:], kidBuffer)
		kid = binary.BigEndian.Uint64(buffer)
	}
	if header[0]&0x8 == 0 {
		ctr = uint64(header[0] & 0x7)
	} else {
		ctrLen = int(header[0]&0x7) + 1
		buffer := make([]byte, 8)
		ctrBuffer := header[1+kidLen : 1+kidLen+ctrLen]
		copy(buffer[8-ctrLen:], ctrBuffer)
		ctr = binary.BigEndian.Uint64(buffer)
	}

	return kid, ctr, 1 + kidLen + ctrLen
}
