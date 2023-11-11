package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
)

type SHISHUA struct {
	state   [16]uint64
	output  [16]uint64
	counter [4]uint64
}

var phi = [16]uint64{
	0x9E3779B97F4A7C15, 0xF39CC0605CEDC834, 0x1082276BF3A27251, 0xF86C6A11D0C18E95,
	0x2767F0B153D27B7F, 0x0347045B5BF1827F, 0x01886F0928403002, 0xC1D64BA40F335E36,
	0xF06AD7AE9717877E, 0x85839D6EFFBD7DC6, 0x64D325D1C5371682, 0xCADD0CCCFDFFBBE1,
	0x626E33B8D04B4331, 0xBBF73C790D94F79D, 0x471C4AB3ED3D82A5, 0xFEC507705E4AE6E5,
}

func (srng *SHISHUA) shuffle() {
	for j := 0; j < 2; j++ {
		s := srng.state[j*8 : (j+1)*8]
		o := srng.output[j*4 : (j+1)*4]
		var t [8]uint64

		for k := 0; k < 4; k++ {
			s[k+4] += srng.counter[k]
		}

		shufOffsets := []uint8{2, 3, 0, 1, 5, 6, 7, 4, 3, 0, 1, 2, 6, 7, 4, 5}
		for k := 0; k < 8; k++ {
			t[k] = (s[shufOffsets[k]] >> 32) | (s[shufOffsets[k+8]] << 32)
		}

		for k := 0; k < 4; k++ {
			uLo := s[k] >> 1
			uHi := s[k+4] >> 3
			s[k] = uLo + t[k]
			s[k+4] = uHi + t[k+4]
			o[k] = uLo ^ t[k+4]
		}
	}

	for j := 0; j < 4; j++ {
		srng.output[j+8] = srng.state[j] ^ srng.state[j+12]
		srng.output[j+12] = srng.state[j+8] ^ srng.state[j+4]
		srng.counter[j] += 7 - uint64(j*2)
	}
}

func (srng *SHISHUA) Uint64() uint64 {
	out := srng.output[0]
	srng.shuffle()
	return out
}

/*
	func (srng *SHISHUA) Seed(seed int64) {
		srng.Seed64(uint64(seed))
	}
*/
func (srng *SHISHUA) prngGen(buf []byte, size int) []byte {
	if buf == nil {
		panic("buf is nil")
	}
	for i := 0; i < size; i += 128 {
		for j := 0; j < 16; j++ {
			binary.LittleEndian.PutUint64(buf[i+j*8:], srng.Uint64())
		}
	}

	return buf
}

func (srng *SHISHUA) Read(buf []byte) (n int, err error) {
	size := cap(buf)
	if size%128 != 0 {
		panic("buf's size must be a multiple of 128 bytes.")
	}
	return copy(buf, srng.prngGen(buf, size)), nil
}

func NewSHISHUA() *SHISHUA {
	srng := &SHISHUA{}

	buf := make([]byte, 64)
	if n, e := rand.Read(buf); n != 64 || e != nil {
		panic("rand.Read failed")
	}

	var seed [4]uint64
	for i := 0; i < 4; i++ {
		seed[i] = uint64(buf[i*8+0]) | uint64(buf[i*8+1])<<8 | uint64(buf[i*8+2])<<16 | uint64(buf[i*8+3])<<24
	}

	copy(srng.state[:], phi[:])
	for i := 0; i < 4; i++ {
		srng.state[i*2+0] ^= seed[i]
		srng.state[i*2+8] ^= seed[(i+2)%4]
	}

	const rounds = 13
	for i := 0; i < rounds; i++ {
		srng.shuffle()
		for j := 0; j < 4; j++ {
			srng.state[j] = srng.output[j+12]
			srng.state[j+4] = srng.output[j+8]
			srng.state[j+8] = srng.output[j+4]
			srng.state[j+12] = srng.output[j]
		}
	}

	return srng
}

func main() {
	s := NewSHISHUA()

	buf := make([]byte, 128)

	var occurrences = make(map[string]struct{})

	for i := 0; i < 100; i++ {
		n, _ := s.Read(buf)
		if n != cap(buf) {
			panic("n != cap(buf)")
		}
		// spew.Dump(buf[:n])
		str := hex.EncodeToString(buf)
		if _, ok := occurrences[str]; ok {
			panic("duplicate hex")
		}
		occurrences[str] = struct{}{}
		_, _ = os.Stdout.WriteString(str)
		_, _ = os.Stdout.WriteString("\n")
	}

	for i := 0; i < 5000; i++ {
		str := fmt.Sprintf("%x", s.Uint64())
		if _, ok := occurrences[str]; ok {
			panic("duplicate uint64")
		}
	}
}
