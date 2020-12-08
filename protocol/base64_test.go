package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type testData struct {
	StringData  string           `json:"string_data"`
	EncodedData URLEncodedBase64 `json:"encoded_data"`
}

func TestBase64UnmarshalJSON(t *testing.T) {
	message := "test base64 data"

	expected := testData{
		StringData:  "test string",
		EncodedData: URLEncodedBase64(message),
	}

	encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
	raw := fmt.Sprintf(`{"string_data": "test string", "encoded_data": "%s"}`, encoded)

	got := testData{}
	err := json.NewDecoder(strings.NewReader(raw)).Decode(&got)
	if err != nil {
		t.Fatalf("error decoding JSON: %v", err)
	}

	if !bytes.Equal(expected.EncodedData, got.EncodedData) {
		t.Fatalf("invalid URLEncodedBase64 data received: expected %s got %s", expected.EncodedData, got.EncodedData)
	}
	if expected.StringData != got.StringData {
		t.Fatalf("invalid string data received: expected %s got %s", expected.StringData, got.StringData)
	}
}

func TestBase64UnmarshalJSONWithNull(t *testing.T) {

	expected := testData{
		StringData:  "test string",
		EncodedData: nil,
	}

	raw := fmt.Sprint(`{"string_data": "test string", "encoded_data": null}`)

	got := testData{}
	err := json.NewDecoder(strings.NewReader(raw)).Decode(&got)
	if err != nil {
		t.Fatalf("error decoding JSON: %v", err)
	}

	if !bytes.Equal(expected.EncodedData, got.EncodedData) {
		t.Fatalf("invalid URLEncodedBase64 data received: expected %s got %s", expected.EncodedData, got.EncodedData)
	}
	if expected.StringData != got.StringData {
		t.Fatalf("invalid string data received: expected %s got %s", expected.StringData, got.StringData)
	}
}

func TestBase64MarshalJSON(t *testing.T) {
	message := "test base64 data"

	expected := testData{
		StringData:  "test string",
		EncodedData: URLEncodedBase64(message),
	}

	encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
	raw := fmt.Sprintf(`{"string_data":"test string","encoded_data":"%s"}`, encoded)

	b := &strings.Builder{}
	err := json.NewEncoder(b).Encode(expected)

	if err != nil {
		t.Fatalf("error encoding JSON: %v", err)
	}
	got := b.String()
	got = strings.TrimSuffix(got, "\n")
	if raw != got {
		t.Fatalf("invalid json encoded: expected %q got %q", raw, got)
	}
}

func TestBase64MarshalJSONWithNull(t *testing.T) {
	expected := testData{
		StringData:  "test string",
		EncodedData: nil,
	}

	raw := fmt.Sprintf(`{"string_data":"test string","encoded_data":null}`)

	b := &strings.Builder{}
	err := json.NewEncoder(b).Encode(expected)

	if err != nil {
		t.Fatalf("error encoding JSON: %v", err)
	}
	got := b.String()
	got = strings.TrimSuffix(got, "\n")
	if raw != got {
		t.Fatalf("invalid json encoded: expected %q got %q", raw, got)
	}
}
