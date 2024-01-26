package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	mathrand "math/rand"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/salsa20/salsa"
)

func Sha256(data []byte) []byte {
	ret := sha256.Sum256(data)
	return ret[:]
}

// split a slice into smaller slices of size "chunkSize" each
func SplitIntoChunks(data []byte, chunkSize int) [][]byte {
	if len(data)%chunkSize != 0 {
		panic("len(data) % chunkSize != 0")
	}
	chunkCount := len(data) / chunkSize
	chunks := make([][]byte, chunkCount)
	for i := 0; i < chunkCount; i++ {
		chunks[i] = data[i*chunkSize : (i+1)*chunkSize]
	}
	return chunks
}

func Assert(condition bool) {
	if !condition {
		panic("assert failed")
	}
}

// port of sodium.crypto_generichash
func Generichash(length int, msg []byte) []byte {
	h, err := blake2b.New(length, nil)
	if err != nil {
		panic("error in generichash")
	}
	_, err = h.Write(msg)
	if err != nil {
		panic("error in generichash")
	}
	return h.Sum(nil)
}

func Decrypt_generic(plaintext []byte, key []byte, nonce int) []byte {
	return Encrypt_generic(plaintext, key, nonce)
}

func Encrypt_generic(plaintext []byte, key []byte, nonce int) []byte {
	pXk := XorBytes(plaintext, key)
	ro := randomOracle(key, uint32(nonce))
	out := XorBytes(pXk, ro)
	return out
}

func XorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("len(a) != len(b)")
	}
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// flatten a slice of slices into a slice
func Flatten(sos [][]byte) []byte {
	var res []byte
	for i := 0; i < len(sos); i++ {
		res = append(res, sos[i]...)
	}
	return res
}

// use a fixed-key Salsa20 as a random permutator. Instead of the nonce/counter,
// we feed the data that needs to be permuted.
func randomOracle(msg []byte, t uint32) []byte {
	if len(msg) != 16 {
		panic(len(msg) != 16)
	}
	// We need a 32-byte key because we use Salsa20. The last 4
	// bytes will be filled with the index of the circuit's wire.
	fixedKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 0, 0, 0, 0}
	tBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, t)
	copy(fixedKey[28:32], tBytes)
	out := make([]byte, 16)
	var msgArray [16]byte
	copy(msgArray[:], msg)
	// will xor Salsa20 output with 2nd arg and output the result into 1st arg
	salsa.XORKeyStream(out, out, &msgArray, &fixedKey)
	return out
}

func Decrypt(a, b []byte, t uint32, m []byte) []byte {
	return Encrypt(a, b, t, m)
}

// Based on the the A4 method from Fig.1 and the D4 method in Fig6 of the BHKR13 paper
// (https://eprint.iacr.org/2013/426.pdf)
// Note that the paper doesn't prescribe a specific method to break the symmerty between A and B,
// so we choose a circular byte shift instead of a circular bitshift as in Fig6.
func Encrypt(a, b []byte, t uint32, m []byte) []byte {
	// double a
	a2 := make([]byte, 16)
	copy(a2[:], a[:])
	leastbyte := make([]byte, 1)
	copy(leastbyte, a2[0:1])
	copy(a2[:], a2[1:15])      // Logical left shift by 1 byte
	copy(a2[14:15], leastbyte) // Restore old least byte as new greatest (non-pointer) byte
	// quadruple b
	b4 := make([]byte, 16)
	copy(b4[:], b[:])
	leastbytes := make([]byte, 2)
	copy(leastbytes, b4[0:2])
	copy(b4[:], b4[2:15])       // Logical left shift by 2 bytes
	copy(b4[13:15], leastbytes) // Restore old least two bytes as new greatest bytes

	k := XorBytes(a2, b4)
	ro := randomOracle(k, t)
	mXorK := XorBytes(m, k)
	return XorBytes(mXorK, ro)
}

// convert bytes into a 0/1 array with least bit at index 0
func BytesToBits(b []byte) []int {
	bytes := new(big.Int).SetBytes(b)
	bits := make([]int, len(b)*8)
	for i := 0; i < len(bits); i++ {
		bits[i] = int(bytes.Bit(i))
	}
	return bits
}

// convert an array of 0/1 with least bit at index 0 into bytes
func BitsToBytes(b []int) []byte {
	bigint := new(big.Int)
	for i := 0; i < len(b); i++ {
		bigint.SetBit(bigint, i, uint(b[i]))
	}
	// we want to preserver any leading zeroes in the bytes
	byteLength := int(math.Ceil(float64(len(b)) / 8))
	buf := make([]byte, byteLength)
	bigint.FillBytes(buf)
	return buf
}

// reverses elements order in slice of int, returns a new slice of int
func Reverse(s []int) []int {
	newSlice := make([]int, len(s))
	copy(newSlice, s)
	for i, j := 0, len(newSlice)-1; i < j; i, j = i+1, j-1 {
		newSlice[i], newSlice[j] = newSlice[j], newSlice[i]
	}
	return newSlice
}

// concatenate slices of bytes into a new slice with a new underlying array
func Concat(slices ...[]byte) []byte {
	totalSize := 0
	for _, v := range slices {
		totalSize += len(v)
	}
	newSlice := make([]byte, totalSize)
	copiedSoFar := 0
	for _, v := range slices {
		copy(newSlice[copiedSoFar:copiedSoFar+len(v)], v)
		copiedSoFar += len(v)
	}
	return newSlice
}

// concatenate slices of bytes pointed to by pointers into a new slice with
// a new underlying array
func ConcatP(pointers ...*[]byte) []byte {
	totalSize := 0
	for _, v := range pointers {
		totalSize += len(*v)
	}
	newSlice := make([]byte, totalSize)
	copiedSoFar := 0
	for _, v := range pointers {
		copy(newSlice[copiedSoFar:copiedSoFar+len(*v)], *v)
		copiedSoFar += len(*v)
	}
	return newSlice
}

// finishes sha256 hash from a previous mid-state
func FinishHash(outerState []byte, data []byte) []byte {
	digest := sha256.New()
	digestUnmarshaler, ok := digest.(encoding.BinaryUnmarshaler)
	if !ok {
		panic("d does not implement UnmarshalBinary")
	}
	// sha256.go expects the state to be formatted in a certain way
	var state []byte
	magic256 := "sha\x03"
	state = append(state, magic256...)
	state = append(state, outerState...)
	// expects the previous chunk, can be set to zeroes
	state = append(state, make([]byte, 64)...)
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], 64) // 64 bytes processed so far
	state = append(state, a[:]...)
	if err := digestUnmarshaler.UnmarshalBinary(state); err != nil {
		panic("error in UnmarshalBinary")
	}
	digest.Write(data)
	return digest.Sum(nil)
}

// GetRandom returns a random slice of specified size
func GetRandom(size int) []byte {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return randomBytes
}

// convert big.Int into a slice of 16 bytes
func To16Bytes(x *big.Int) []byte {
	buf := make([]byte, 16)
	x.FillBytes(buf)
	return buf
}

// convert big.Int into a slice of 32 bytes
func To32Bytes(x *big.Int) []byte {
	buf := make([]byte, 32)
	x.FillBytes(buf)
	return buf
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func gf_2_128_mul(authKey, y, R *big.Int) *big.Int {
	// we don't want to change authKey. making a copy of it
	x := new(big.Int).Set(authKey)
	one := big.NewInt(1)
	res := big.NewInt(0)
	tmp := big.NewInt(0)
	tmp2 := big.NewInt(0)
	for i := 127; i > -1; i-- {
		// res ^= x * ((y >> i) & 1n)
		tmp.Rsh(y, uint(i))
		tmp.And(tmp, one)
		tmp.Mul(x, tmp)
		res.Xor(res, tmp)
		// x = (x >> 1n) ^ ((x & 1n) * BigInt(0xE1000000000000000000000000000000))
		tmp.And(x, one)
		tmp.Mul(tmp, R) //R is global
		tmp2.Rsh(x, 1)
		x.Xor(tmp2, tmp)
	}
	return res
}

// check if int is in array
func Contains(n int, h []int) bool {
	for _, v := range h {
		if v == n {
			return true
		}
	}

	return false
}

/// -------------------------------RANDOM OLD STUFF

// func getTag(w http.ResponseWriter, req *http.Request) {
// 	fmt.Println("in getTag", req.RemoteAddr)
// 	defer req.Body.Close()
// 	body, err := ioutil.ReadAll(req.Body)
// 	if err != nil {
// 		panic("can't read request body")
// 	}
// 	if len(body) != (128 + 16) {
// 		panic("len(body != 128+16")
// 	}
// 	encZero := body[:16]
// 	//mask := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 3, 4, 3, 3, 3, 3}
// 	//Hmasked := xorBytes(encZero, mask)
// 	encReq := body[16 : 128+16]

// 	// type 0x16 = Handshake; TLS Version 1.2; 16 bytes of plaintext data
// 	lenEncReq := make([]byte, 2)
// 	binary.BigEndian.PutUint16(lenEncReq, uint16(len(encReq)))
// 	aad := []byte{0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3}
// 	aad = append(aad, lenEncReq...)
// 	//tag1 := getAuthTag(aad, encReq, mask, nil)
// 	//tag2 := getAuthTag(aad, encReq, Hmasked, nil)
// 	//tag := xorBytes(tag1, tag2)
// 	tag := getAuthTag(aad, encReq, encZero, nil)

// 	fmt.Println("sending back ghash output ", tag)

// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Connection", "close")
// 	w.Write(tag)
// }

// // compute the GHASH function to get authentication tag for AES-GCM encryption
// func gHash(inputs [][]byte, encZero []byte) []byte {
// 	// polynomial := 2**128+2**7+2**2+2+1
// 	_1 := big.NewInt(1)
// 	_2 := big.NewInt(2)
// 	_7 := big.NewInt(7)
// 	_128 := big.NewInt(128)

// 	poly := big.NewInt(0)
// 	poly.Add(poly, new(big.Int).Exp(_2, _128, nil))
// 	poly.Add(poly, new(big.Int).Exp(_2, _7, nil))
// 	poly.Add(poly, new(big.Int).Exp(_2, _2, nil))
// 	poly.Add(poly, _2)
// 	poly.Add(poly, _1)

// 	H := new(big.Int).SetBytes(encZero)
// 	S := big.NewInt(0)

// 	for i := 0; i < len(inputs); i++ {
// 		inp := new(big.Int).SetBytes(inputs[i])
// 		out := new(big.Int).Xor(S, inp)
// 		out.Mul(out, H)
// 		out.Mod(out, poly)
// 		S = out
// 	}
// 	return S.Bytes()
// }

// func getAuthTag(aad, ct, encZero_, gctrBlock []byte) []byte {
// 	// there is no need to use precompute on the notary side
// 	//table := preComputeTable(encZero)
// 	var inputs []byte
// 	inputs = append(inputs, aad...)
// 	if len(aad)%16 > 0 {
// 		inputs = append(inputs, make([]byte, 16-(len(aad)%16))...)
// 	}
// 	inputs = append(inputs, ct...)
// 	if len(ct)%16 > 0 {
// 		inputs = append(inputs, make([]byte, 16-(len(ct)%16))...)
// 	}
// 	lenA := make([]byte, 8)
// 	binary.BigEndian.PutUint64(lenA, uint64(len(aad)*8))
// 	inputs = append(inputs, lenA...)
// 	lenC := make([]byte, 8)
// 	binary.BigEndian.PutUint64(lenC, uint64(len(ct)*8))
// 	inputs = append(inputs, lenC...)

// 	S := big.NewInt(0)
// 	X := new(big.Int)
// 	encZero := new(big.Int).SetBytes(encZero_)
// 	for i := 0; i < len(inputs)/16; i++ {
// 		X.SetBytes(inputs[i*16 : i*16+16])
// 		X.Xor(X, S)
// 		//S = times_auth_key_old(X, table)
// 		S = blockMult(X, encZero)
// 		//fmt.Println("after round", i, "S.Bytes()", S.Bytes())
// 	}
// 	if gctrBlock != nil {
// 		// if gctrBlock is nil, the output omits the final xor with gctrBlock
// 		S = S.Xor(S, new(big.Int).SetBytes(gctrBlock))
// 	}
// 	return S.Bytes()
// }

// // ported from https://github.com/bozhu/AES-GCM-Python/blob/master/aes_gcm.py
// func gf_2_128_mul(authKey, y *big.Int) *big.Int {
// 	// we don't want to change authKey. making a copy of it
// 	x := new(big.Int).Set(authKey)
// 	res := big.NewInt(0)
// 	tmp := big.NewInt(0)
// 	tmp2 := big.NewInt(0)
// 	for i := 127; i > -1; i-- {
// 		// res ^= x * ((y >> i) & 1n)
// 		tmp.Rsh(y, uint(i))
// 		tmp.And(tmp, g.One)
// 		tmp.Mul(x, tmp)
// 		res.Xor(res, tmp)
// 		// x = (x >> 1n) ^ ((x & 1n) * BigInt(0xE1000000000000000000000000000000))
// 		tmp.And(x, g.One)
// 		tmp.Mul(tmp, g.R) //r is global
// 		tmp2.Rsh(x, 1)
// 		x.Xor(tmp2, tmp)
// 	}
// 	return res
// }

// // this is not in use but keeping it here in case we may need it in the future
// func preComputeTable(encZero []byte) [][]*big.Int {
// 	authKey := new(big.Int).SetBytes(encZero)
// 	var table [][]*big.Int
// 	tmp := new(big.Int)
// 	tmp2 := new(big.Int)
// 	for i := 0; i < 16; i++ {
// 		var row []*big.Int
// 		for j := 0; j < 256; j++ {
// 			tmp2.SetUint64(uint64(j))
// 			tmp.Lsh(tmp2, uint(8*i)) //j << (8n*i)
// 			row = append(row, gf_2_128_mul(authKey, tmp))
// 		}
// 		table = append(table, row)
// 	}
// 	return table
// }

// // this may be used in the future if we decide to use a precomputed Htable
// func times_auth_key_old(val *big.Int, table [][]*big.Int) *big.Int {
// 	res := big.NewInt(0)
// 	_255 := big.NewInt(255)
// 	idx := new(big.Int)
// 	for i := 0; i < 16; i++ {
// 		idx.And(val, _255)
// 		res.Xor(res, table[i][idx.Uint64()]) // res ^= table[i][val & BigInt(0xFF)]
// 		val.Rsh(val, 8)                      // val >>= 8n
// 	}
// 	return res
// }

// func blockMult(val, encZero *big.Int) *big.Int {
// 	res := big.NewInt(0)
// 	_255 := big.NewInt(255)
// 	j := new(big.Int)
// 	for i := 0; i < 16; i++ {
// 		j.And(val, _255)
// 		j.Lsh(j, uint(8*i))
// 		res.Xor(res, gf_2_128_mul(encZero, j))
// 		val.Rsh(val, 8) // val >>= 8n
// 	}
// 	return res
// }

// func randomOracle(msg []byte, nonce_ int) []byte {
// 	// sha(0)
// 	var sha0 [32]byte
// 	sha0_, err := hex.DecodeString("da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8")
// 	if err != nil {
// 		panic(err)
// 	}
// 	copy(sha0[:], sha0_[:])
// 	var nonce [24]byte
// 	result := make([]byte, 4)
// 	binary.BigEndian.PutUint32(result, uint32(nonce_))
// 	// JIGG puts e.g. 277 = [0,0,1,21] in reverse order into nonce i.e [21, 1, 0,0,0...,0]
// 	for i := 0; i < 4; i++ {
// 		copy(nonce[i:i+1], result[3-i:4-i])
// 	}
// 	out := secretbox.Seal(nil, msg, &nonce, &sha0)
// 	return out[0:16]
// }

func RandString() string {
	mathrand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[mathrand.Intn(len(letterRunes))]
	}
	return string(b)
}

// expand the range [min:max] into array of ints 1,2,3,4... up to but not including max
func ExpandRange(min int, max int) []int {
	arr := make([]int, max-min)
	for i := 0; i < len(arr); i++ {
		arr[i] = min + i
	}
	return arr
}

func AESGCMencrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// we don't reuse plaintext slice when encrypting
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return Concat(nonce, ciphertext)
}

// decrypt and reuse the ciphertext slice to put plaintext into it
func AESGCMdecrypt(key []byte, ctWithNonce []byte) []byte {
	nonce := ctWithNonce[0:12]
	ct := ctWithNonce[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	pt, err := aesgcm.Open(ct[:0], nonce, ct, nil)
	if err != nil {
		panic(err.Error())
	}
	return pt
}

// AEC-CTR encrypt data, setting initial counter to 0
func AESCTRencrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// AEC-CTR decrypt data, setting initial counter to 0
func AESCTRdecrypt(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext
}

// AEC-ECB encrypt data
func AESECBencrypt(key []byte, plaintext []byte) []byte {
	if len(plaintext)%16 != 0 {
		panic("len(plaintext) % 16 != 0")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	// there is no dedicated ECB mode in golang, crypting block by block
	ciphertext := make([]byte, len(plaintext))
	blockCount := len(plaintext) / 16
	for i := 0; i < blockCount; i++ {
		block.Encrypt(ciphertext[i*16:i*16+16], plaintext[i*16:i*16+16])
	}
	return ciphertext
}

func RandInt(min, max int) int {
	mathrand.Seed(int64(binary.BigEndian.Uint64(GetRandom(8))))
	return mathrand.Intn(max-min) + min
}

func ECDSASign(key *ecdsa.PrivateKey, items ...[]byte) []byte {
	var concatAll []byte
	for _, item := range items {
		concatAll = append(concatAll, item...)
	}
	digest_to_be_signed := Sha256(concatAll)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest_to_be_signed)
	if err != nil {
		panic("ecdsa.Sign")
	}
	signature := append(To32Bytes(r), To32Bytes(s)...)
	return signature
}

func ECDSAPubkeyToPEM(key *ecdsa.PublicKey) []byte {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		fmt.Println(err)
		panic("x509.MarshalPKIXPublicKey")
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pubKeyPEM := pem.EncodeToMemory(block)
	return pubKeyPEM
}
