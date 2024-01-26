package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	at "notary/aes_tag"
	"notary/evaluator"
	"notary/garbled_pool"
	"notary/garbler"
	"notary/ghash"
	"notary/meta"
	"notary/ote"
	"notary/paillier2pc"
	u "notary/utils"

	"os"
	"path/filepath"
	"time"
)

// stream counter counts how many bytes passed through it
type StreamCounter struct {
	total uint32
}

func (sc *StreamCounter) Write(p []byte) (int, error) {
	n := len(p)
	sc.total += uint32(n)
	if sc.total > 1024*1024*300 {
		panic("can't process blob more than 300MB")
	}
	return n, nil
}

// The description of each step of the TLS PRF computation, both inside the
// garbled circuit and outside of it:
// [REF 1] https://github.com/tlsnotary/circuits/blob/master/README

// Session implement a TLSNotary session
type Session struct {
	e     *evaluator.Evaluator
	g     *garbler.Garbler
	p2pc  *paillier2pc.Paillier2PC
	ghash *ghash.GHASH
	// gctrBlockShare is notary's share of the AES-GCM's GCTR block
	// for the client's request
	gctrBlockShare []byte
	// serverPubkey is EC pubkey used during 3-party ECDH secret negotiation.
	// This pubkey will be included in notary's signature
	serverPubkey []byte
	// notaryPMSShare is notary's additive share of TLS pre-master secret. It is the result of
	// computing point addition jointly with the client using our Paillier-based protocol.
	notaryPMSShare []byte
	// ghashInputsBlob contains a blob of inputs for the ghash function. It will
	// be included into the notary's final signature.
	ghashInputsBlob []byte
	// cwkShare is notary's xor share of client_write_key
	cwkShare []byte
	// civShare is notary's xor share of client_write_iv
	civShare []byte
	// swkShare is notary's xor share of server_write_key
	swkShare []byte
	// sivShare is notary's xor share of server_write_iv
	sivShare []byte
	// notaryKey is a symmetric key used to encrypt messages TO the client
	notaryKey []byte
	// clientKey is a symmetric key used to decrypt messages FROM the client
	clientKey []byte
	// SigningKey is an ephemeral key used to sign the notarization session
	SigningKey ecdsa.PrivateKey
	// StorageDir is where the blobs from the client are stored
	StorageDir string
	// msgsSeen contains a list of all messages seen from the client
	msgsSeen []int

	Ot               *ote.Manager
	lastOtResponse   []byte
	lastResponseFrom string

	// PmsOuterHashState is the state of the outer hash of HMAC needed to compute the PMS
	PmsOuterHashState []byte
	// MsOuterHashState is the state of the outer hash of HMAC needed to compute the MS
	MsOuterHashState []byte
	// hisCommitment is client's salted commitment for each circuit
	hisCommitment [][]byte
	// encodedOutput is notary's encoded output for each circuit
	encodedOutput [][]byte
	// c6CheckValue is encoded outputs and decoding table which must the sent to
	// Client as part of dual execution garbling. We store it here until Client
	// sends her commitment. Then we send it out.
	c6CheckValue []byte
	// meta contains information about circuits
	meta []*meta.Circuit
	// Tt are file handles for truth tables which are used
	// to stream directly to the HTTP response (saving memory)
	Tt [][]*os.File
	// dt are decoding tables for each execution of each garbled circuit
	dt [][][]byte
	// streamCounter is used when client uploads his blob to the notary
	streamCounter *StreamCounter
	// Gp is used to access the garbled pool
	Gp *garbled_pool.GarbledPool
	// Tv is used to access tag verification manager
	Tv *at.TagVerificationManager
	// Ts is used to access tag signing manager
	Ts *at.TagSigningManager
	// tag verification masks obtained from prepTagVerification step
	tagMask string
	pohMask string
	// Sid is the id of this session, used to signal to session manager when the
	// session can be destroyed
	Sid string
	// DestroyChan is the chan to which to send Sid when this session needs
	// to be destroyed
	DestroyChan chan string
	// notify manager that the session releases OT ownership
	OtReleaseChan chan string
}

// Init is the first message from the client. It starts Oblivious Transfer
// setup and we also initialize all of Session's structures.
func (s *Session) Init(body []byte) []byte {
	s.sequenceCheck(1)
	s.g = new(garbler.Garbler)
	s.e = new(evaluator.Evaluator)
	s.p2pc = new(paillier2pc.Paillier2PC)
	s.ghash = new(ghash.GHASH)
	// the first 64 bytes are client pubkey for ECDH
	o := 0
	s.clientKey, s.notaryKey = s.getSymmetricKeys(body[o:o+64], &s.SigningKey)
	o += 64
	c6Count := int(new(big.Int).SetBytes(body[o : o+2]).Uint64())
	o += 2

	u.Assert(len(body) == o)

	s.ghash.Init()

	curDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	s.StorageDir = filepath.Join(filepath.Dir(curDir), u.RandString())
	err = os.Mkdir(s.StorageDir, 0755)
	if err != nil {
		panic(err)
	}

	// get already garbled circuits ...
	blobs := s.Gp.GetBlobs(c6Count)
	// and separate into input labels, truth tables, decoding table
	il := make([][][]byte, len(s.Gp.Circuits))
	s.Tt = make([][]*os.File, len(s.Gp.Circuits))
	s.dt = make([][][]byte, len(s.Gp.Circuits))
	// depending on the number of circuit executions, there may be more than
	// one Blob for every circuit
	for i := 1; i < len(s.Gp.Circuits); i++ {
		il[i] = make([][]byte, len(blobs[i]))
		s.Tt[i] = make([]*os.File, len(blobs[i]))
		s.dt[i] = make([][]byte, len(blobs[i]))
		for j, blob := range blobs[i] {
			il[i][j] = *blob.Il
			s.Tt[i][j] = blob.TtFile
			s.dt[i][j] = *blob.Dt
		}
	}

	s.meta = s.Gp.Circuits
	s.g.Init(il, s.meta, c6Count)
	s.e.Init(s.meta, c6Count)
	s.hisCommitment = make([][]byte, len(s.g.Cs))
	s.encodedOutput = make([][]byte, len(s.g.Cs))

	s.p2pc.Init()
	return nil
}

// GetBlob returns file handles to truth tables
func (s *Session) GetBlob(encrypted []byte) []*os.File {
	s.sequenceCheck(3)
	// flatten into one slice
	var flat []*os.File
	for _, sliceOfFiles := range s.Tt {
		if len(sliceOfFiles) == 0 {
			continue
		}
		flat = append(flat, sliceOfFiles...)
	}
	return flat
}

// SetBlobChunk stores a blob from the client.
func (s *Session) SetBlob(respBody io.ReadCloser) []byte {
	s.sequenceCheck(4)
	path := filepath.Join(s.StorageDir, "blobForNotary")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	s.streamCounter = &StreamCounter{total: 0}
	body := io.TeeReader(respBody, s.streamCounter)
	_, err2 := io.Copy(file, body)
	if err2 != nil {
		panic("err2 != nil")
	}
	return nil
}

func (s *Session) GetUploadProgress(dummy []byte) []byte {
	// special case. This message may be repeated many times
	s.sequenceCheck(100)
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, s.streamCounter.total)
	return s.encryptToClient(bytes)
}

// Step1 starts a Paillier 2PC of EC point addition
func (s *Session) Step1(encrypted []byte) []byte {
	s.sequenceCheck(5)
	body := s.decryptFromClient(encrypted)
	var resp []byte
	s.serverPubkey, resp = s.p2pc.Step1(body)
	return s.encryptToClient(resp)
}

func (s *Session) Step2(encrypted []byte) []byte {
	s.sequenceCheck(6)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.p2pc.Step2(body))
}

func (s *Session) Step3(encrypted []byte) []byte {
	s.sequenceCheck(7)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.p2pc.Step3(body))
}

func (s *Session) Step4(encrypted []byte) []byte {
	s.sequenceCheck(8)
	body := s.decryptFromClient(encrypted)
	s.notaryPMSShare = s.p2pc.Step4(body)
	return nil
}

// [REF 1] Step 2
func (s *Session) C1_step1(encrypted []byte) []byte {
	s.sequenceCheck(9)
	s.setCircuitInputs(1, s.notaryPMSShare, s.g.Cs[1].Masks[1])
	out := s.c_step1(1)
	return s.encryptToClient(out)
}

// [REF 1] Step 2
func (s *Session) C1_step2(encrypted []byte) []byte {
	s.sequenceCheck(10)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(1, body))
}

// [REF 1] Step 4. N computes a1 and passes it to C.
func (s *Session) C1_step3(encrypted []byte) []byte {
	s.sequenceCheck(11)
	body := s.decryptFromClient(encrypted)
	output := s.processDecommit(1, body[:len(body)-32])
	hisInnerHash := body[len(body)-32:]
	// unmask the output
	s.PmsOuterHashState = u.XorBytes(output[0:32], s.g.Cs[1].Masks[1])
	a1 := u.FinishHash(s.PmsOuterHashState, hisInnerHash)
	return s.encryptToClient(a1)
}

// [REF 1] Step 6. N computes a2 and passes it to C.
func (s *Session) C1_step4(encrypted []byte) []byte {
	s.sequenceCheck(12)
	body := s.decryptFromClient(encrypted)
	a2 := u.FinishHash(s.PmsOuterHashState, body)
	return s.encryptToClient(a2)
}

// [REF 1] Step 8. N computes p2 and passes it to C.
func (s *Session) C1_step5(encrypted []byte) []byte {
	s.sequenceCheck(13)
	body := s.decryptFromClient(encrypted)
	p2 := u.FinishHash(s.PmsOuterHashState, body)
	return s.encryptToClient(p2)
}

// [REF 1] Step 10.
func (s *Session) C2_step1(encrypted []byte) []byte {
	s.sequenceCheck(14)
	s.setCircuitInputs(2, s.PmsOuterHashState, s.g.Cs[2].Masks[1])
	out := s.c_step1(2)
	return s.encryptToClient(out)
}

// [REF 1] Step 12.
func (s *Session) C2_step2(encrypted []byte) []byte {
	s.sequenceCheck(15)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(2, body))

}

// [REF 1] Step 14 and Step 21. N computes a1 and a1 and sends it to C.
func (s *Session) C2_step3(encrypted []byte) []byte {
	s.sequenceCheck(16)
	body := s.decryptFromClient(encrypted)
	output := s.processDecommit(2, body[:len(body)-64])
	a1inner := body[len(body)-64 : len(body)-32]
	a1inner_vd := body[len(body)-32:]
	// unmask the output
	s.MsOuterHashState = u.XorBytes(output[0:32], s.g.Cs[2].Masks[1])
	a1 := u.FinishHash(s.MsOuterHashState, a1inner)
	a1_vd := u.FinishHash(s.MsOuterHashState, a1inner_vd)
	return s.encryptToClient(u.Concat(a1, a1_vd))
}

// [REF 1] Step 16 and Step 23. N computes a2 and verify_data and sends it to C.
func (s *Session) C2_step4(encrypted []byte) []byte {
	s.sequenceCheck(17)
	body := s.decryptFromClient(encrypted)
	a2inner := body[:32]
	p1inner_vd := body[32:64]
	a2 := u.FinishHash(s.MsOuterHashState, a2inner)
	verifyData := u.FinishHash(s.MsOuterHashState, p1inner_vd)[:12]
	return s.encryptToClient(u.Concat(a2, verifyData))
}

// [REF 1] Step 18.
func (s *Session) C3_step1(encrypted []byte) []byte {
	s.sequenceCheck(18)
	g := s.g
	s.setCircuitInputs(3,
		s.MsOuterHashState,
		g.Cs[3].Masks[1],
		g.Cs[3].Masks[2],
		g.Cs[3].Masks[3],
		g.Cs[3].Masks[4])
	// the masks become notary's TLS key shares
	s.swkShare = s.g.Cs[3].Masks[1]
	s.cwkShare = s.g.Cs[3].Masks[2]
	s.sivShare = s.g.Cs[3].Masks[3]
	s.civShare = s.g.Cs[3].Masks[4]

	out := s.c_step1(3)
	return s.encryptToClient(out)
}

// [REF 1] Step 18. Notary doesn't need to parse the circuit's output because
// the masks that he inputted become his TLS keys' shares.
func (s *Session) C3_step2(encrypted []byte) []byte {
	s.sequenceCheck(19)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(3, body))
}

// [REF 1] Step 18.
func (s *Session) C4_step1(encrypted []byte) []byte {
	s.sequenceCheck(20)
	body := s.decryptFromClient(encrypted)
	// to save a round-trip, circuit 3 piggy-backs on this message to parse the
	// decommitment. Notary doesn't need to parse the output of the circuit,
	// since we already know what out TLS key shares are
	decommitSize := len(s.encodedOutput[3]) + len(u.Concat(s.dt[3]...)) + 32
	s.processDecommit(3, body[:decommitSize])

	g := s.g
	s.setCircuitInputs(4,
		s.swkShare,
		s.cwkShare,
		s.sivShare,
		s.civShare,
		g.Cs[4].Masks[1],
		g.Cs[4].Masks[2])

	s.c4_step1A()
	inputLabels := s.g.GetNotaryLabels(4)
	return s.encryptToClient(inputLabels)
}

func (s *Session) c4_step1A() {
	// We need to make sure that the same input labels which we give
	// to the client for c4's client_write_key (cwk) and client_write_iv
	// (civ) will also be given for all invocations of circuit 6. This ensures
	// that client cannot deliberately corrupt his
	// HTTP request by providing the wrong cwk/civ share.

	// because of the dual execution, both client and notary need to
	// receive their input labels via OT.
	// we process client's OT request and create a notary's OT request.
	cl4 := s.g.GetClientLabels(4)

	allC6Labels := s.g.GetClientLabels(6)
	var c6KeyLabels []byte
	labelsForEachExecution := u.SplitIntoChunks(allC6Labels, len(allC6Labels)/s.g.C6Count)
	for i := 0; i < s.g.C6Count; i++ {
		// take labels for input bits 0-160
		c6KeyLabels = append(c6KeyLabels, labelsForEachExecution[i][:160*32]...)
	}

	go func() {
		// send the labels as is without any encryption
		err := s.Ot.RespondWithData(append(cl4, c6KeyLabels...))
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		step2OtResp, err := s.Ot.RequestData(s.g.Cs[4].InputBits)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		s.lastOtResponse = step2OtResp
		s.lastResponseFrom = "c4_step1"
	}()
}

// [REF 1] Step 18.
func (s *Session) C4_step2(encrypted []byte) []byte {
	s.sequenceCheck(21)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(4, body))
}

// compute MAC for Client_Finished using Oblivious Transfer
// see https://tlsnotary.org/how_it_works#section4
// (4. Computing MAC of the request using Oblivious Transfer. )
func (s *Session) C4_step3(encrypted []byte) []byte {
	s.sequenceCheck(22)
	body := s.decryptFromClient(encrypted)
	// Notary doesn't need to parse circuit's 4 output because
	// the masks that he inputted become his TLS keys' shares.
	s.processDecommit(4, body[:len(body)-16])
	body = body[len(body)-16:]
	g := s.g
	o := 0
	encCF := body[o : o+16]
	o += 16

	// Both N and C can locally compute their shares of H^1 and H^2.
	// In order to compute shares of H^3, they must perform:
	// (H1_n + H1_c)(H2_n + H2_c) = H1_n*H2_n + H1_n*H2_c + H1_c*H2_n + H1_c*H2_c
	// Terms 1 and 4 are computed locally by N and C resp.
	// For terms 2 and 3, N provides the Xtable and C provides the bits of y (obliviously)

	// Notary's mask for H for circuit 4 becomes his share of H^1
	s.ghash.P[1] = g.Cs[4].Masks[1]
	s.ghash.P[2] = ghash.BlockMult(s.ghash.P[1], s.ghash.P[1])
	H1H2 := ghash.BlockMult(s.ghash.P[1], s.ghash.P[2])

	allMessages1, maskSum1 := ghash.GetMaskedXTable(s.ghash.P[1])
	allMessages2, maskSum2 := ghash.GetMaskedXTable(s.ghash.P[2])

	// otReq contains a concatenation of client's H1 bits and H2 bits.
	// Client's H1 is multiplied with notary's H2 and client's
	// H2 is multiplied with notary's H1.
	go func() {
		err := s.Ot.RespondWithData(u.Concat(allMessages2, allMessages1))
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}
	}()

	s.ghash.P[3] = u.XorBytes(u.XorBytes(maskSum1, maskSum2), H1H2)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}

	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	// Notary's mask for gctr block for circuit 4 becomes his share of gctr block
	gctrShare := g.Cs[4].Masks[2]

	// aad, encCF, lenAlenC are 3 input blocks for the GHASH function.
	// L is the total count of GHASH blocks. n is the index of the input block
	// starting from 0. We multiply GHASH input block X[n] by power H^(L-n).
	// In out case for L=3, we multiply X[0] by H^3, X[1] by H^2, X[2] by H^1
	s1 := ghash.BlockMult(aad, s.ghash.P[3])
	s2 := ghash.BlockMult(encCF, s.ghash.P[2])
	s3 := ghash.BlockMult(lenAlenC, s.ghash.P[1])
	tagShare := u.XorBytes(u.XorBytes(u.XorBytes(s1, s2), s3), gctrShare)

	return s.encryptToClient(tagShare)
}

// [REF 1] Step 26.
func (s *Session) C5_pre1(encrypted []byte) []byte {
	s.sequenceCheck(23)
	body := s.decryptFromClient(encrypted)
	a1inner := body[:]
	a1 := u.FinishHash(s.MsOuterHashState, a1inner)

	return s.encryptToClient(a1)
}

// [REF 1] Step 28.
func (s *Session) C5_step1(encrypted []byte) []byte {
	s.sequenceCheck(24)
	s.setCircuitInputs(5,
		s.MsOuterHashState,
		s.swkShare,
		s.sivShare,
		s.g.Cs[5].Masks[1],
		s.g.Cs[5].Masks[2])
	u.Assert(len(s.g.Cs[5].InputBits)/8 == 84)
	out := s.c_step1(5)
	return s.encryptToClient(out)
}

// [REF 1] Step 28.
func (s *Session) C5_step2(encrypted []byte) []byte {
	s.sequenceCheck(25)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(5, body))
}

// compute MAC for Server_Finished using Oblivious Transfer
// see also coments in C3_step3
func (s *Session) C5_step3(encrypted []byte) []byte {
	s.sequenceCheck(26)
	body := s.decryptFromClient(encrypted)
	s.processDecommit(5, body[:len(body)-16])
	body = body[len(body)-16:]
	g := s.g
	o := 0
	encSF := body[o : o+16]
	o += 16

	h1share := g.Cs[5].Masks[1]
	h2share := ghash.BlockMult(h1share, h1share)
	H1H2 := ghash.BlockMult(h1share, h2share)

	allMessages1, maskSum1 := ghash.GetMaskedXTable(h1share)
	allMessages2, maskSum2 := ghash.GetMaskedXTable(h2share)

	// otReq is a concatenation of client's H1 bits and H2 bits.
	// Client's H1 is multiplied with to notary's H2 and client's
	// H2 is multiplied with notary's H1.
	go func() {
		err := s.Ot.RespondWithData(u.Concat(allMessages2, allMessages1))
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}
	}()

	H3share := u.XorBytes(u.XorBytes(maskSum1, maskSum2), H1H2)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0}
	//lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
	lenAlenC := []byte{0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128}

	gctrShare := g.Cs[5].Masks[2]

	s1 := ghash.BlockMult(aad, H3share)
	s2 := ghash.BlockMult(encSF, h2share)
	s3 := ghash.BlockMult(lenAlenC, h1share)
	tagShare := u.XorBytes(u.XorBytes(u.XorBytes(s1, s2), s3), gctrShare)

	return s.encryptToClient(tagShare)
}

func (s *Session) C6_step1(encrypted []byte) []byte {
	s.sequenceCheck(27)
	var allInputs [][]byte
	for i := 0; i < s.g.C6Count; i++ {
		allInputs = append(allInputs, s.cwkShare)
		allInputs = append(allInputs, s.civShare)
	}
	s.setCircuitInputs(6, allInputs...)

	// ---------------------------------------
	// instead of the usual c_step1B, we have a special case:
	// we need to remove all the labels corresponding to client_write_key
	// and client_write_iv, because client already has the correct
	// active labels for those input bits and so he did not include them into
	// this OT request. Those labels were given to him in c4_step1B().
	allLabels := s.g.GetClientLabels(6)
	var labels []byte
	labelsForEachExecution := u.SplitIntoChunks(allLabels, len(allLabels)/s.g.C6Count)
	for i := 0; i < s.g.C6Count; i++ {
		// leave out labels for input bits 0-160
		labels = append(labels, labelsForEachExecution[i][160*32:]...)
	}
	// proceed with the regular step1 flow
	// ---------------------------------------

	inputLabels := s.g.GetNotaryLabels(6)
	go func() {
		err := s.Ot.RespondWithData(labels)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		step2OtResp, err := s.Ot.RequestData(s.g.Cs[6].InputBits)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		s.lastOtResponse = step2OtResp
		s.lastResponseFrom = "c6_step1"
	}()

	return s.encryptToClient(inputLabels)
}

func (s *Session) C6_pre2(encrypted []byte) []byte {
	s.sequenceCheck(28)
	body := s.decryptFromClient(encrypted)
	// add a dummy 32-byte commitment to keep common_step2() happy
	body = append(body, make([]byte, 32)...)
	s.c6CheckValue = s.common_step2(6, body)
	// do not send c6CheckValue until Client sends his commitment
	return nil
}

func (s *Session) C6_step2(encrypted []byte) []byte {
	s.sequenceCheck(29)
	body := s.decryptFromClient(encrypted)
	u.Assert(len(body) == 32)
	s.hisCommitment[6] = body
	return s.encryptToClient(s.c6CheckValue)
}

func (s *Session) C7_step1(encrypted []byte) []byte {
	s.sequenceCheck(30)
	body := s.decryptFromClient(encrypted)
	decommitSize := len(s.encodedOutput[6]) + len(u.Concat(s.dt[6]...)) + 32
	s.processDecommit(6, body[:decommitSize])
	g := s.g
	var allInputs [][]byte
	allInputs = append(allInputs, s.cwkShare)
	allInputs = append(allInputs, s.civShare)
	allInputs = append(allInputs, g.Cs[7].Masks[1])

	s.gctrBlockShare = g.Cs[7].Masks[1]
	s.setCircuitInputs(7, allInputs...)
	out := s.c_step1(7)
	return s.encryptToClient(out)
}

func (s *Session) C7_step2(encrypted []byte) []byte {
	s.sequenceCheck(31)
	body := s.decryptFromClient(encrypted)
	return s.encryptToClient(s.common_step2(7, body))
}

// compute MAC for client's request using Oblivious Transfer
func (s *Session) Ghash_step1(encrypted []byte) []byte {
	s.sequenceCheck(32)
	body := s.decryptFromClient(encrypted)
	decommitSize := len(s.encodedOutput[7]) + len(u.Concat(s.dt[7]...)) + 32
	s.processDecommit(7, body[:decommitSize])
	body = body[decommitSize:]
	o := 0
	mpnBytes := body[o : o+2]
	o += 2
	maxPowerNeeded := int(binary.BigEndian.Uint16(mpnBytes))
	s.ghash.SetMaxPowerNeeded(maxPowerNeeded)
	if s.ghash.GetMaxOddPowerNeeded() == 3 {
		// The Client must not have request any OT
		u.Assert(len(body) == 2)
		//perform free squaring on powers 2,3 which we have from client finished
		ghash.FreeSquare(&s.ghash.P, maxPowerNeeded)
		return nil
	}

	u.Assert(len(body) == o)

	allEntries := s.ghash.Step1()
	go func() {
		err := s.Ot.RespondWithData(allEntries)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}
	}()
	return nil
}

// This step is optional and is only used when the client's request is larger
// than 339*16=5424 bytes (see maxHTable in Ghash_step1)
// The reason why this step is separated from Ghash_step1 is because it requires
// a second round of communication.
func (s *Session) Ghash_step2(encrypted []byte) []byte {
	s.sequenceCheck(33)
	allEntries := s.ghash.Step2()
	go func() {
		err := s.Ot.RespondWithData(allEntries)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}
	}()
	return nil
}

// compute MAC for client's request using Oblivious Transfer. Stage 2: Block
// Aggregation.
func (s *Session) Ghash_step3(encrypted []byte) []byte {
	s.sequenceCheck(34)
	body := s.decryptFromClient(encrypted)
	o := 0
	maxPowerNeeded := s.ghash.GetMaxPowerNeeded()
	s.ghashInputsBlob = body[o : o+maxPowerNeeded*16]
	o += maxPowerNeeded * 16
	needsAggregation := body[o:]

	// ghashInputs = aad + client_request + lenAlenC
	ghashInputs := u.SplitIntoChunks(s.ghashInputsBlob, 16)
	ghashOutputShare, allEntries, blockMultCount := s.ghash.Step3(ghashInputs)

	if len(needsAggregation) > 0 {
		// client sent us bits for every small power and for every corresponding
		// aggregated value
		go func() {
			err := s.Ot.RespondWithData(allEntries)
			if err != nil {
				log.Println(err)
				s.OtReleaseChan <- s.Sid
				s.DestroyChan <- s.Sid // destroy self
				return
			}
		}()
	} else {
		// no block aggregation was needed
		u.Assert(blockMultCount == 0)
	}

	return s.encryptToClient(u.XorBytes(s.gctrBlockShare, ghashOutputShare))
}

// Client commit to the server's response (with MACs).
// Notary signs the session.
func (s *Session) CommitHash(encrypted []byte) []byte {
	s.sequenceCheck(35)
	body := s.decryptFromClient(encrypted)
	hisCommitHash := body[0:32]
	hisKeyShareHash := body[32:64]
	hisPMSShareHash := body[64:96]
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	signature := u.ECDSASign(&s.SigningKey,
		hisCommitHash,
		hisKeyShareHash,
		hisPMSShareHash,
		s.ghashInputsBlob,
		s.serverPubkey,
		s.notaryPMSShare,
		s.cwkShare,
		s.civShare,
		s.swkShare,
		s.sivShare,
		timeBytes)

	// this is the last step with Softspoken OT so it can be disconnected
	s.Ot.Disconnect()
	s.OtReleaseChan <- s.Sid

	return s.encryptToClient(u.Concat(
		signature,
		s.notaryPMSShare,
		s.cwkShare,
		s.civShare,
		s.swkShare,
		s.sivShare,
		timeBytes))
}

type prepTagVerificationRequest struct {
	ClientIvShare []byte `json:"clientIvShare"`
	RecordIv      []byte `json:"recordIv"`
}

func (s *Session) PrepTagVerification(body []byte) []byte {
	req := new(prepTagVerificationRequest)
	err := json.Unmarshal(body, req)
	if err != nil {
		resp, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: "invalid body"})

		return resp
	}

	if len(req.ClientIvShare) != len(s.sivShare) {
		resp, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: "invalid client IV share"})

		return resp
	}

	if len(req.RecordIv) != 8 {
		resp, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: "invalid record IV"})

		return resp
	}

	err = s.Tv.HandlePrepTagVerification(s.Sid, s.sivShare, s.swkShare, req.ClientIvShare, req.RecordIv)
	if err != nil {
		resp, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})

		return resp
	}

	return nil
}

type pollTagVerificationResponse struct {
	Busy     bool   `json:"busy"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}

func (s *Session) PollTagVerification(body []byte) []byte {
	busy, tagMask, pohMask, err := s.Tv.HandlePollTagVerificationStatus(s.Sid)

	response := new(pollTagVerificationResponse)
	response.Busy = busy
	response.Complete = len(tagMask) != 0 && len(pohMask) != 0
	if err != nil {
		response.Error = err.Error()
	}

	s.tagMask = tagMask
	s.pohMask = pohMask

	resp, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return []byte("{\"error\":\"internal error\"}")
	}

	return resp
}

type tagVerificationRequest struct {
	Ciphertext []string `json:"ciphertext"`
	AAD        string   `json:"aad"`
	TagShare   string   `json:"tagShare"`
}

type tagVerificationResponse struct {
	Ciphertext []string `json:"ciphertext,omitempty"`
	Signature  string   `json:"signature,omitempty"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
}

func (s *Session) TagVerification(body []byte) []byte {
	s.sequenceCheck(36)

	response := new(tagVerificationResponse)
	if len(s.tagMask) == 0 || len(s.pohMask) == 0 {
		response.Error = "tag verification is not ready"
		response.Status = "failed"
		resp, _ := json.Marshal(response)
		return resp
	}

	req := new(tagVerificationRequest)
	err := json.Unmarshal(body, req)
	if err != nil {
		response.Error = "invalid body"
		response.Status = "failed"
		resp, _ := json.Marshal(response)
		return resp
	}

	success, err := at.VerifyTag(s.Sid, s.pohMask, s.tagMask, req.Ciphertext, req.AAD, req.TagShare)
	if err != nil {
		response.Error = err.Error()
		response.Status = "failed"
		resp, _ := json.Marshal(response)
		return resp
	}

	response.Ciphertext = req.Ciphertext
	if success {
		signature, err := s.Ts.Sign(response.Ciphertext)
		if err != nil {
			log.Println("TagVerification:", err)
			response.Status = "failed"
			response.Error = "failed to sign ciphertext"
		} else {
			response.Status = "verified"
			response.Signature = hex.EncodeToString(signature)
		}
	} else {
		response.Status = "failed"
	}

	resp, _ := json.Marshal(response)
	return resp
}

// getSymmetricKeys computes a shared ECDH secret between the other party's
// pubkey and my privkey. Outputs 2 16-byte secrets.
func (s *Session) getSymmetricKeys(pk []byte, myPrivKey *ecdsa.PrivateKey) (ck, nk []byte) {
	hisPubKey := ecdsa.PublicKey{
		elliptic.P256(),
		new(big.Int).SetBytes(pk[0:32]),
		new(big.Int).SetBytes(pk[32:64]),
	}
	secret, _ := hisPubKey.Curve.ScalarMult(hisPubKey.X, hisPubKey.Y, myPrivKey.D.Bytes())
	secretBytes := u.To32Bytes(secret)
	return secretBytes[0:16], secretBytes[16:32]
}

func (s *Session) decryptFromClient(ctWithNonce []byte) []byte {
	return u.AESGCMdecrypt(s.clientKey, ctWithNonce)
}

func (s *Session) encryptToClient(plaintext []byte) []byte {
	return u.AESGCMencrypt(s.notaryKey, plaintext)
}

// sequenceCheck makes sure messages are received in the correct order and
// (where applicable) received only once. This is crucial for the security
// of the TLSNotary protocol.
func (s *Session) sequenceCheck(seqNo int) {
	if seqNo == 100 {
		// This is the GetUploadProgress message. It is an optional message.
		// It may be repeated many times. It must come after SetBlob (msg no 4).
		// Due to async nature of client's JS, it may be sent asyncly even
		// after client finished uploading (but not later than msg 9).
		if u.Contains(4, s.msgsSeen) && !u.Contains(9, s.msgsSeen) {
			// if clause contains the permitted conditions
		} else {
			panic("msg No 5 received out of order")
		}
		// we dont store this messages
		return
	}
	if u.Contains(seqNo, s.msgsSeen) {
		panic("message sent twice")
	}
	if !u.Contains(seqNo-1, s.msgsSeen) {
		// it is acceptable if the preceding message was not found if:
		// 1) the msg is the very first msg "init"
		// 2) the msg is getBlob/setBlob (no 3/4) and the client hasn't yet
		// sent "init2" (no 2). Happens if client's connection speed is very
		// fast.
		// 3) the msg is no 34, and no 33 (Ghash_step2) which is optional, was
		// skipped
		if u.Contains(seqNo, []int{1, 3, 4}) || (seqNo == 34 && u.Contains(32, s.msgsSeen)) {
			// if clause contains the permitted conditions
		} else {
			panic("previous message not seen")
		}
	}
	s.msgsSeen = append(s.msgsSeen, seqNo)
}

// returns truth tables for the circuit number cNo from the
// blob which we received earlier from the client
func (s *Session) RetrieveBlobsForNotary(cNo int) []byte {
	off, ttSize := s.getCircuitBlobOffset(cNo)
	path := filepath.Join(s.StorageDir, "blobForNotary")
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, ttSize)
	_, err = file.ReadAt(buffer, int64(off))
	if err != nil && err != io.EOF {
		panic(err)
	}
	tt := buffer[:ttSize]
	return tt
}

// GetCircuitBlobOffset finds the offset and size of the tt+dt blob for circuit cNo
// in the blob of all circuits
func (s *Session) getCircuitBlobOffset(cNo int) (int, int) {
	offset := 0
	ttLen := 0
	for i := 1; i < len(s.g.Cs); i++ {
		offset += ttLen
		ttLen = s.g.Cs[i].Meta.AndGateCount * 48
		if i == 6 {
			ttLen = s.g.C6Count * ttLen
		}
		if i == cNo {
			break
		}
	}
	return offset, ttLen
}

// c_step1 is common for all circuits
func (s *Session) c_step1(cNo int) []byte {
	inputLabels := s.g.GetNotaryLabels(cNo)

	go func() {
		// respond to a request
		err := s.Ot.RespondWithData(s.g.GetClientLabels(cNo))
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		// request the same thing from the other party
		step2OtResp, err := s.Ot.RequestData(s.g.Cs[cNo].InputBits)
		if err != nil {
			log.Println(err)
			s.OtReleaseChan <- s.Sid
			s.DestroyChan <- s.Sid // destroy self
			return
		}

		s.lastOtResponse = step2OtResp
		s.lastResponseFrom = fmt.Sprintf("c%d_step1", cNo)
	}()

	return inputLabels
}

// given a slice of circuit inputs in the same order as expected by the c*.casm file,
// convert each input into a bit array with the least bit of each input at index[0]
func (s *Session) setCircuitInputs(cNo int, inputs ...[]byte) {
	for _, v := range inputs {
		s.g.Cs[cNo].InputBits = append(s.g.Cs[cNo].InputBits, u.BytesToBits(v)...)
	}
}

// common_step2 is Step2 which is the same for all circuits. Returns a value
// which must be sent to the Client as part of dual execution garbling.
func (s *Session) common_step2(cNo int, body []byte) []byte {
	ttBlob := s.RetrieveBlobsForNotary(cNo)
	notaryLabels, clientLabels, clientCommitment := s.parse_step2(cNo, body)
	s.hisCommitment[cNo] = clientCommitment
	s.encodedOutput[cNo] = s.e.Evaluate(cNo, notaryLabels, clientLabels, ttBlob)
	return u.Concat(s.encodedOutput[cNo], u.Concat(s.dt[cNo]...))
}

// parse_step2 is common for all circuits. Returns notary's and client's input
// labels for the circuit number cNo.
// Notary is acting as the evaluator. Client sent his input labels in the clear
// and he also sent notary's input labels via OT.
func (s *Session) parse_step2(cNo int, body []byte) ([]byte, []byte, []byte) {
	o := 0
	// exeCount is how many executions of this circuit we need
	exeCount := []int{0, 1, 1, 1, 1, 1, s.g.C6Count, 1}[cNo]
	allClientLabelsSize := s.g.Cs[cNo].Meta.ClientInputSize * 16 * exeCount
	clientLabels := body[o : o+allClientLabelsSize]
	o += allClientLabelsSize
	clientCommitment := body[o : o+32]
	o += 32
	u.Assert(o == len(body))

	// stupid fix for a data race where this is called by the client before this side received an OT response
	// for the previous step
	expectedLastResponseSource := fmt.Sprintf("c%d_step1", cNo)
	for s.lastResponseFrom != expectedLastResponseSource {
		time.Sleep(5 * time.Millisecond)
	}
	notaryLabels := s.lastOtResponse

	return notaryLabels, clientLabels, clientCommitment
}

// processDecommit processes Client's decommitment, makes sure it matches the
// commitment, decodes and parses the Notary's circuit output.
// Client committed first, then Notary revealed his encoded outputs and
// decoding table and now the Client decommits.
func (s *Session) processDecommit(cNo int, decommit []byte) []byte {
	o := 0
	hisEncodedOutput := decommit[o : o+len(s.encodedOutput[cNo])]
	o += len(s.encodedOutput[cNo])
	myDecodingTable := u.Concat(s.dt[cNo]...)
	hisDecodingTable := decommit[o : o+len(myDecodingTable)]
	o += len(myDecodingTable)
	hisSalt := decommit[o : o+32]
	o += 32
	u.Assert(o == len(decommit))
	u.Assert(bytes.Equal(s.hisCommitment[cNo], u.Sha256(u.Concat(
		hisEncodedOutput, hisDecodingTable, hisSalt))))
	// decode his output, my output and compare them
	hisPlaintext := u.XorBytes(myDecodingTable, hisEncodedOutput)
	myPlaintext := u.XorBytes(hisDecodingTable, s.encodedOutput[cNo])
	u.Assert(bytes.Equal(hisPlaintext, myPlaintext))
	output := s.parsePlaintextOutput(cNo, myPlaintext)
	return output
}

// parsePlaintextOutput parses the plaintext of each circuit execution into
// output bit and converts the output bits into a flat slice of bytes so that
// output values are in the same order as they appear in the *.casm files
func (s *Session) parsePlaintextOutput(cNo int, ptBytes []byte) []byte {
	c := (s.meta)[cNo]
	exeCount := []int{0, 1, 1, 1, 1, 1, s.g.C6Count, 1}[cNo]
	chunks := u.SplitIntoChunks(ptBytes, len(ptBytes)/exeCount)
	var output []byte
	for i := 0; i < exeCount; i++ {
		// plaintext has a padding in MSB to make it a multiple of 8 bits. We
		// decompose into bits and drop the padding
		outBits := u.BytesToBits(chunks[i])[0:c.OutputSize]
		// reverse output bits so that the values of the output be placed in
		// the same order as they appear in the *.casm files
		outBytes := s.parseOutputBits(cNo, outBits)
		output = append(output, outBytes...)
	}
	return output
}

// parseOutputBits converts the output bits of the circuit into a flat slice
// of bytes so that output values are in the same order as they appear in the *.casm files
func (s *Session) parseOutputBits(cNo int, outBits []int) []byte {
	o := 0 // offset
	var outBytes []byte
	for _, v := range (s.meta)[cNo].OutputsSizes {
		output := u.BitsToBytes(outBits[o : o+v])
		outBytes = append(outBytes, output...)
		o += v
	}
	if o != (s.meta)[cNo].OutputSize {
		panic("o != e.g.Cs[cNo].OutputSize")
	}
	return outBytes
}
