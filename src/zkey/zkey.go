package zkey

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ZkeyHttpHandler struct {
	provingKeys   map[int][]byte
	verifyingKeys map[int][]byte

	lastModified time.Time
}

func NewZkeyHandler(zkeyDir string) (*ZkeyHttpHandler, error) {
	entries, err := os.ReadDir(zkeyDir)
	if err != nil {
		return nil, err
	}

	keysRegEx := regexp.MustCompilePOSIX("^[1-9]{1}[0-9]*\\.(zkey|json)$")

	keyCounter := make(map[int]int, 0)
	// count files with the name <number>.zkey or <number>.json.
	// when we count to for a <number>, we have both zkey and json files with the sames names,
	// therefore we can load them as keys
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if keysRegEx.MatchString(entry.Name()) {
			name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
			keyName, err := strconv.Atoi(name)
			if err != nil {
				log.Println(err)
				continue
			}

			if _, ok := keyCounter[keyName]; !ok {
				keyCounter[keyName] = 0
			}

			keyCounter[keyName] += 1
		}
	}

	handler := new(ZkeyHttpHandler)
	handler.provingKeys = make(map[int][]byte)
	handler.verifyingKeys = make(map[int][]byte)
	handler.lastModified = time.Now()

	for keyName, keyCount := range keyCounter {
		if keyCount != 2 {
			continue
		}

		log.Printf("Loading ZK key pair for %d AES blocks\n", keyName)
		pkey, err := os.ReadFile(filepath.Join(zkeyDir, fmt.Sprintf("%d.zkey", keyName)))
		if err != nil {
			log.Printf("Failed to read %d.zkey, skipping. Reason: %s\n", keyName, err)
			continue
		}
		vkey, err := os.ReadFile(filepath.Join(zkeyDir, fmt.Sprintf("%d.json", keyName)))
		if err != nil {
			log.Printf("Failed to read %d.json, skipping. Reason: %s\n", keyName, err)
			continue
		}

		handler.provingKeys[keyName] = pkey
		handler.verifyingKeys[keyName] = vkey
	}

	log.Printf("Loaded %d ZK key pairs\n", len(handler.provingKeys))
	return handler, nil
}

type supportedBlockSizeResponse struct {
	Sizes []int `json:"sizes"`
}

func (h *ZkeyHttpHandler) GetSupportedBlockSizes(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	keys := make([]int, 0, len(h.provingKeys))
	for k := range h.provingKeys {
		keys = append(keys, k)
	}

	response := new(supportedBlockSizeResponse)
	response.Sizes = keys

	body, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

type getKeysResponse struct {
	Pk    []byte `json:"pk,omitempty"`
	Vk    []byte `json:"vk,omitempty"`
	Size  int    `json:"size,omitempty"`
	Error string `json:"error,omitempty"`
}

func splitBytesIntoChunks(data []byte, chunkSize int) [][]byte {
	dataLen := len(data)
	numChunks := (dataLen + chunkSize - 1) / chunkSize // Calculate the number of chunks needed

	chunks := make([][]byte, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := (i + 1) * chunkSize
		if end > dataLen {
			end = dataLen
		}
		chunks[i] = data[start:end]
	}

	return chunks
}

func (h *ZkeyHttpHandler) GetKeys(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sizeStr := req.URL.Query().Get("size")
	if sizeStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	desiredSize, err := strconv.Atoi(sizeStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := new(getKeysResponse)

	pkey, ok := h.provingKeys[desiredSize]
	if !ok {
		response.Error = fmt.Sprintf("no keys of size %d", desiredSize)
		body, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write(body)
		return
	}

	vkey, ok := h.verifyingKeys[desiredSize]
	if !ok {
		log.Printf("WARNING: proving key for size %d exist but verifying key doesn't\n", desiredSize)
		response.Error = fmt.Sprintf("no keys of size %d", desiredSize)
		body, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write(body)
		return
	}

	response.Pk = pkey
	response.Vk = vkey
	response.Size = desiredSize

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Last-Modified", h.lastModified.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"zkey-%d.json\"", desiredSize))

	body, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("x-content-length", fmt.Sprintf("%d", len(body)))

	flusher, ok := w.(http.Flusher)
	if !ok {
		// response writer doesn't support flushing, write the whole response in one go
		w.Write(body)
		return
	}

	chunks := splitBytesIntoChunks(body, 8192)

	for _, chunk := range chunks {
		w.Write(chunk)
		flusher.Flush() // flushing will trigger chunked encoding
	}
}
