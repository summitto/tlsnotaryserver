package ote

import (
	"errors"
	"fmt"
	"log"

	ot "github.com/summitto/ot-wrapper/pkg"
)

type Manager struct {
	native ot.OTManagerGo
	port   int
}

func NewManager(port int) (*Manager, error) {
	var err error = nil
	defer func() {
		recoveredErr := recover()
		if recoveredErr != nil {
			strError, ok := recoveredErr.(string)
			if ok {
				err = errors.New(strError)
			} else {
				err = errors.New("OT unknown error")
			}
		}
	}()

	nativeManager := ot.NewOTManagerGo(true, false)

	return &Manager{
		native: nativeManager,
		port:   port,
	}, err
}

func (m *Manager) Listen() error {
	if m.native.IsConnected() {
		return errors.New("busy")
	}

	var err error = nil
	defer func() {
		recoveredErr := recover()
		if recoveredErr != nil {
			strError, ok := recoveredErr.(string)
			if ok {
				err = errors.New(strError)
			} else {
				err = errors.New("OT unknown error")
			}
		}
	}()

	// this will block until the client is connected
	m.native.Connect(fmt.Sprintf("0.0.0.0:%d", m.port))

	return err
}

func (m *Manager) Disconnect() {
	m.native.Disconnect()
}

func (m *Manager) IsConnected() bool {
	return m.native.IsConnected()
}

func (m *Manager) RequestData(choices []int) (result []byte, err error) {
	if !m.native.IsConnected() {
		log.Println("OT request failed - not connected")
		return nil, errors.New("not connected")
	}

	defer func() {
		recoveredErr := recover()
		if recoveredErr != nil {
			strError, ok := recoveredErr.(string)
			if ok {
				err = errors.New(strError)
			} else {
				err = errors.New("OT unknown error")
			}
		}
	}()

	// transform 0/1 ints to little-endian bytes, packed with those 0/1s
	preparedChoices, clear := arrayBitsToLittleEndianBytes(choices)
	defer clear()

	log.Println("OT requesting", len(choices), "blocks")
	resultBuf := m.native.RequestData(preparedChoices, int64(len(choices)))
	defer ot.DeleteUInt8Vector(resultBuf)
	log.Println("OT request done!")

	for i := 0; i < int(resultBuf.Size()); i++ {
		result = append(result, resultBuf.Get(i))
	}

	return
}

func (m *Manager) RespondWithData(data []byte) (err error) {
	if !m.native.IsConnected() {
		log.Println("OT respond failed - not connected")
		return errors.New("not connected")
	}

	defer func() {
		recoveredErr := recover()
		if recoveredErr != nil {
			strError, ok := recoveredErr.(string)
			if ok {
				err = errors.New(strError)
			} else {
				err = errors.New("OT unknown error")
			}
		}
	}()

	input := ot.NewUInt8Vector()
	defer ot.DeleteUInt8Vector(input)

	for _, val := range data {
		input.Add(val)
	}

	log.Println("OT responding with", len(data), "bytes")
	m.native.RespondWithData(input)
	log.Println("OT responding done!")
	return
}

func (m *Manager) Finish() {
	defer func() {
		if err := recover(); err != nil {
			log.Println("OT shutdown error:", err)
		}
	}()

	if m.IsConnected() {
		m.Disconnect()
	}
	if m.native != nil {
		ot.DeleteOTManagerGo(m.native)
	}
	m.native = nil
}

func arrayBitsToLittleEndianBytes(bits []int) (result ot.UInt8Vector, cleanup func()) {
	result = ot.NewUInt8Vector()

	for i := 0; i < len(bits); i += 8 {
		var val byte = 0
		for j := 0; j < 8 && i+j < len(bits); j++ {
			choice := bits[i+j]
			if choice == 1 {
				val |= 1 << j
			}
		}

		result.Add(val)
	}

	cleanup = func() {
		ot.DeleteUInt8Vector(result)
	}

	return
}
