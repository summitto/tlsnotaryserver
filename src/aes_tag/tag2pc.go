package aes_tag

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/summitto/aesmpc"
)

func checkPortMpcRange(port int) bool {
	ports := [4]int{port, port + 1, port + 2, port + 3}

	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("0.0.0.0:%d", p), time.Second)
		if err == nil {
			conn.Close()
			return false
		}
	}

	return true
}

func (t *TagVerificationManager) runEncryptedIvMpc(doneCh chan string, port int, serverKeyShare string, iv string) {
	tagMask, err := aesmpc.RunGcmEncryptedIvServer(port, t.circuitDir, serverKeyShare, iv)
	if err != nil {
		log.Println("MPC IV:", err)
		doneCh <- ""
		return
	}
	doneCh <- tagMask
}

func (t *TagVerificationManager) runPowersOfHMpc(doneCh chan string, port int, serverKeyShare string) {
	maskedPowersOfH, err := aesmpc.RunGcmPowersOfHServer(port, t.circuitDir, serverKeyShare)
	if err != nil {
		log.Println("MPC PoH:", err)
		doneCh <- ""
		return
	}
	doneCh <- maskedPowersOfH
}

func (t *TagVerificationManager) runTagVerificationMpcAsync(serverKeyShare string, iv string, tagMaskResultCh chan string, pohMaskResultCh chan string, startNotifyCh chan bool, errCh chan error) {
	errBusy := errors.New("tag verification mpc is busy")
	if !checkPortMpcRange(t.portIv) || !checkPortMpcRange(t.portPoH) {
		startNotifyCh <- false
		errCh <- errBusy
	}

	go t.runEncryptedIvMpc(tagMaskResultCh, t.portIv, serverKeyShare, iv)
	go t.runPowersOfHMpc(pohMaskResultCh, t.portPoH, serverKeyShare)

	startNotifyCh <- true
}
