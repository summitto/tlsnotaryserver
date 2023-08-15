package main

// #cgo LDFLAGS: -Laesmpc/ -lcrypto -lssl -laesmpc -ldl -lpthread
import "C"

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"net/http"
	_ "net/http/pprof"
	at "notary/aes_tag"
	"notary/garbled_pool"
	"notary/key_manager"
	"notary/ote"
	"notary/session"
	"notary/session_manager"
	"notary/zkey"

	"time"
)

var sm *session_manager.SessionManager
var gp *garbled_pool.GarbledPool
var km *key_manager.KeyManager

// URLFetcherDoc is the document returned by the deterministic URLFetcher enclave
// https://github.com/tlsnotary/URLFetcher
// It contains AWS HTTP API requests with Amazon's attestation
var URLFetcherDoc []byte

// readBody extracts the HTTP request's body
func readBody(req *http.Request) []byte {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		panic("can't read request body")
	}
	return body
}

// writeResponse appends the CORS headers needed to keep the browser happy
// and writes data to the wire
func writeResponse(resp []byte, w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
	log.Println("wrote response of size: ", len(resp))
}

func getURLFetcherDoc(w http.ResponseWriter, req *http.Request) {
	log.Println("in getURLFetcherDoc", req.RemoteAddr)
	writeResponse(URLFetcherDoc, w)
}

// destroyOnPanic will be called on panic(). It will destroy the session which
// caused the panic
func destroyOnPanic(s *session.Session) {
	r := recover()
	if r == nil {
		return // there was no panic
	}
	fmt.Println("caught a panic message: ", r)
	debug.PrintStack()
	s.DestroyChan <- s.Sid
	s.OtReleaseChan <- s.Sid
}

func httpHandler(w http.ResponseWriter, req *http.Request) {
	// sessionId is the part of the URL after ?
	sessionId := string(req.URL.RawQuery)
	// command is URL path without the leading /
	command := req.URL.Path[1:]
	commandAllowed := false
	for _, allowedCommand := range session_manager.CommandList {
		if allowedCommand == command {
			commandAllowed = true
			break
		}
	}

	if !commandAllowed {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if commandAllowed && sessionId == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println("got request ", command, " from ", req.RemoteAddr)
	var out []byte
	if command == "init" {
		s := sm.AddSession(sessionId)
		if s == nil {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("OT busy"))
			return
		}
		s.Gp = gp
		key, keyData := km.GetActiveKey()
		s.SigningKey = key
		// keyData is sent to Client unencrypted
		out = append(out, keyData...)
	}
	s := sm.GetSession(sessionId)
	if s == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("session %s not found", sessionId)))
		return
	}
	defer destroyOnPanic(s)
	method := sm.GetMethod(command, sessionId)
	body := readBody(req)
	out = append(out, method(body)...)
	writeResponse(out, w)
	if command == "tagVerification" {
		// this was the final message of the session. Destroying the session...
		s.DestroyChan <- s.Sid
		s.OtReleaseChan <- s.Sid
	}
}

// getBlob is called when user wants to download garbled circuits
func getBlob(w http.ResponseWriter, req *http.Request) {
	log.Println("in getBlob", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	body := readBody(req)
	fileHandles := s.GetBlob(body)
	writeResponse(nil, w)
	// stream directly from file
	for _, f := range fileHandles {
		_, err := io.Copy(w, f)
		if err != nil {
			panic("err != nil")
		}
	}
}

// setBlob is called when user wants to upload garbled circuits
func setBlob(w http.ResponseWriter, req *http.Request) {
	log.Println("in setBlob", req.RemoteAddr)
	s := sm.GetSession(string(req.URL.RawQuery))
	defer destroyOnPanic(s)
	out := s.SetBlob(req.Body)
	writeResponse(out, w)
}

// ping is sent to check if notary is available
func ping(w http.ResponseWriter, req *http.Request) {
	log.Println("in ping", req.RemoteAddr)
	writeResponse(nil, w)
}

// when notary starts we expect the admin to upload a URLFetcher document
// it can be uploaded e.g. with:
// curl --data-binary '@URLFetcherDoc' 127.0.0.1:10012/setURLFetcherDoc
func awaitURLFetcherDoc() {
	serverMux := http.NewServeMux()
	srv := &http.Server{Addr: ":10012", Handler: serverMux}
	signal := make(chan struct{})
	serverMux.HandleFunc("/setURLFetcherDoc", func(w http.ResponseWriter, req *http.Request) {
		URLFetcherDoc = readBody(req)
		log.Println("got URLFetcher doc", string(URLFetcherDoc[:100]))
		close(signal)
	})
	// start a server and wait for signal from HandleFunc
	go func() {
		srv.ListenAndServe()
	}()
	<-signal
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}

// getPubKey sends notary's public key to the client
// only useful when running as a regular non-sandboxed server
func getPubKey(w http.ResponseWriter, req *http.Request) {
	log.Println("in getPubKey", req.RemoteAddr)
	writeResponse(km.MasterPubKeyPEM, w)
}

func getBaseDir() string {
	curDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return filepath.Dir(curDir)
}

// initially the circuits are in the human-readable c*.casm format; assemble.js
// converts them into a "Bristol fashion" format and writes to disk c*.out files
func assembleCircuits() {
	baseDir := getBaseDir()
	circuitsDir := filepath.Join(baseDir, "circuits")
	// if c1.out does not exist, proceed to assemble
	if _, err := os.Stat(filepath.Join(circuitsDir, "c1.out")); os.IsNotExist(err) {
		cmd := exec.Command("node", "assemble.js")
		cmd.Dir = circuitsDir
		log.Println("Assembling circuits. This will take a few seconds...")
		if err := cmd.Run(); err != nil {
			log.Println("Error. Could not run: node assemble.js. Please make sure that node is installed on your system.")
			os.Exit(1)
		}
		log.Println("Finished assembling circuits.")
	}
}

func checkTagVerificationCircuits() string {
	baseDir := getBaseDir()
	circuitsDir := filepath.Join(baseDir, "tagCircuits")

	expectedCircuits := []string{"aes128_full.txt", "gcm_shares_200.txt", "xor128.txt", "xor25600.txt"}

	for _, circuit := range expectedCircuits {
		_, err := os.Stat(filepath.Join(circuitsDir, circuit))
		if err != nil {
			log.Fatalln(err)
		}
	}

	return circuitsDir
}

func main() {
	// uncomment the below to profile the process's RAM usage
	// install with: go get github.com/pkg/profile
	// then run: curl http://localhost:8080/debug/pprof/heap > heap
	// go tool pprof -png heap

	// defer profile.Start(profile.MemProfile).Stop()
	// go func() {
	// 	http.ListenAndServe(":8080", nil)
	// }()

	noSandbox := flag.Bool("no-sandbox", false, "Must be set when not running in a sandboxed environment.")
	flag.Parse()
	log.Println("noSandbox", *noSandbox)

	tagVerificationCircuits := checkTagVerificationCircuits()

	tagSigner, err := at.NewTagSigningManager("signing.key")
	if err != nil {
		log.Fatalln(err)
	}

	km = new(key_manager.KeyManager)
	km.Init()
	otManager, err := ote.NewManager(12345)
	if err != nil {
		log.Fatalln(err)
	}
	assembleCircuits()
	sm = new(session_manager.SessionManager)
	sm.Init(tagVerificationCircuits, 10020, 10030, tagSigner, otManager)
	gp = new(garbled_pool.GarbledPool)
	gp.Init(*noSandbox)

	zkeyHandler, err := zkey.NewZkeyHandler("zkey-content")
	if err != nil {
		log.Fatalln(err)
	}

	mux := http.NewServeMux()

	if !*noSandbox {
		mux.HandleFunc("/getURLFetcherDoc", getURLFetcherDoc)
		go awaitURLFetcherDoc()
	}
	// although getPubKey is only used in noSandbox cases, it still
	// can be useful when debugging sandboxed notary
	mux.HandleFunc("/getPubKey", getPubKey)

	mux.HandleFunc("/getBlob", getBlob)
	mux.HandleFunc("/setBlob", setBlob)
	mux.HandleFunc("/ping", ping)

	mux.HandleFunc("/zkey_sizes", zkeyHandler.GetSupportedBlockSizes)
	mux.HandleFunc("/zkey", zkeyHandler.GetKeys)
	mux.HandleFunc("/signing-key.pem", tagSigner.ServePublicKey)

	// all the other request will end up in the httpHandler
	mux.HandleFunc("/", httpHandler)

	ctx, cancel := context.WithCancel(context.Background())

	server := http.Server{
		Addr:         "0.0.0.0:10011",
		WriteTimeout: 5 * time.Minute,
		ReadTimeout:  1 * time.Minute,
		Handler:      mux,
		BaseContext:  func(l net.Listener) context.Context { return ctx },
	}
	log.Println("Listening on :10011")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		err = server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalln(err)
		}
	}()

	<-c
	log.Println("exiting...")

	go func() {
		<-c
		log.Fatalln("terminating...")
	}()

	gracefullCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := server.Shutdown(gracefullCtx); err != nil {
		log.Printf("shutdown error: %v\n", err)
		defer os.Exit(1)
	}

	defer sm.Cleanup()

	cancel()
}
