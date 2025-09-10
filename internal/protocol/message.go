package protocol

import (
	"encoding/json"
	"fmt"
)

type Message struct {
	ID     int64           `json:"id"`
	Method string          `json:"method"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type StartConfirmBody struct {
	SessionID int64 `json:"sessionId"`
}

// TTY proxy protocol - much simpler!
type TTYDataBody struct {
	Data []byte `json:"data"`
}

type TTYResizeBody struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

type ShellInBody struct {
	Command string `json:"command"`
}

type ShellStdinBody struct {
	Data string `json:"data"`
}

type ShellOutBody struct {
	Data    []byte `json:"data"`
	DataSeq int    `json:"dataSeq"`
}

type KeyExchangeRequest struct {
	ClientIP string `json:"clientIp"`
	Hostname string `json:"hostname"`
}

type KeyExchangeResponse struct {
	PSK string `json:"psk"`
}

type AuthBody struct {
	PSK      string `json:"psk"`
	Hostname string `json:"hostname"`
}

type StartBody struct {
	Hostname string `json:"hostname"`
}

type AuthRequestBody struct {
	Hostname string `json:"hostname"`
}

func NewMessage(id int64, method string, body interface{}) (*Message, error) {
	var bodyData json.RawMessage
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyData = data
	}
	return &Message{
		ID:     id,
		Method: method,
		Body:   bodyData,
	}, nil
}

func (m *Message) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

func UnmarshalMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (m *Message) UnmarshalBody(v interface{}) error {
	if len(m.Body) == 0 {
		return nil
	}
	return json.Unmarshal(m.Body, v)
}
