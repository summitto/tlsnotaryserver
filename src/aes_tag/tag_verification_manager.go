package aes_tag

import (
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"
)

const (
	SYSTEM_OWNER = "_SYSTEM"
)

type TagVerificationManager struct {
	circuitDir string
	portIv     int
	portPoH    int

	mutex     sync.RWMutex
	busy      bool
	owner     string
	startTime time.Time
	pohChan   chan string
	ivChan    chan string
}

func NewTagVerificationManager(circuitDir string, portIvBegin int, portPoHBegin int) *TagVerificationManager {
	return &TagVerificationManager{
		circuitDir: circuitDir,
		portIv:     portIvBegin,
		portPoH:    portPoHBegin,
		pohChan:    make(chan string, 1),
		ivChan:     make(chan string, 1),
	}
}

func (t *TagVerificationManager) HandlePrepTagVerification(sessionId string, serverIvShare []byte, serverWriteKeyShare []byte, clientIvShare []byte, recordIv []byte) error {
	t.mutex.RLock()
	busy := t.busy
	t.mutex.RUnlock()

	errBusy := errors.New("tag verification mpc is busy")
	if busy {
		return errBusy
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.busy {
		return errBusy
	}

	if !checkPortMpcRange(t.portIv) || !checkPortMpcRange(t.portPoH) {
		if t.owner == "" {
			// one of the ports is busy, the manager doesn't know MPC is running and owner is not set = ports are occupied by the system
			t.owner = SYSTEM_OWNER
			log.Println("WARNING: TagVerificationManager: one of the MPC ports is occupied by the system, please reconfigure the MPC ports.")
		}
		t.busy = true
		return errBusy
	}

	// xor notary's server iv share and client's server iv share to get to actual record IV
	recordIV := make([]byte, len(serverIvShare))
	for idx := range recordIV {
		recordIV[idx] = serverIvShare[idx] ^ clientIvShare[idx]
	}

	// append first 8 bytes of the record to IV to get record nonce
	nonce := append(recordIV, recordIv...)
	mpcIV := hex.EncodeToString(nonce) + "00000001"

	startNotifyCh := make(chan bool)
	mpcErrCh := make(chan error)

	go t.runTagVerificationMpcAsync(hex.EncodeToString(serverWriteKeyShare), mpcIV, t.ivChan, t.pohChan, startNotifyCh, mpcErrCh)
	mpcStarted := <-startNotifyCh

	if !mpcStarted {
		// there was an error starting MPC, check error channel
		err := <-mpcErrCh
		return err
	}

	t.busy = true
	t.owner = sessionId
	t.startTime = time.Now()

	return nil
}

func (t *TagVerificationManager) HandlePollTagVerificationStatus(sessionId string) (bool, string, string, error) {
	t.mutex.RLock()
	busy := t.busy
	owner := t.owner == sessionId
	systemOwned := t.owner == SYSTEM_OWNER
	hasIv := len(t.ivChan) != 0
	hasPoh := len(t.pohChan) != 0
	t.mutex.RUnlock()

	if systemOwned {
		return true, "", "", errors.New("tag verification MPC cannot be started due to misconfiguration")
	}

	// only MPC owner can check results
	if !owner {
		return busy, "", "", nil
	}

	if !hasIv || !hasPoh {
		return true, "", "", nil
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	tagMask := <-t.ivChan
	pohMask := <-t.pohChan
	t.busy = false
	t.owner = ""

	log.Println("Tag verification MPC result obtained after", time.Since(t.startTime).String())

	return false, tagMask, pohMask, nil
}
