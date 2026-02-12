/*

Copyright 2021 Andrey Devyatkin.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/jsonmessage"
)

func TestToImageIdentifier_BothFields(t *testing.T) {
	id := ImageId{digest: "sha256:abc123", tag: "v1.0"}
	identifier, err := id.ToImageIdentifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identifier.ImageDigest == nil || *identifier.ImageDigest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %v", identifier.ImageDigest)
	}
	if identifier.ImageTag == nil || *identifier.ImageTag != "v1.0" {
		t.Errorf("expected tag v1.0, got %v", identifier.ImageTag)
	}
}

func TestToImageIdentifier_DigestOnly(t *testing.T) {
	id := ImageId{digest: "sha256:abc123", tag: ""}
	identifier, err := id.ToImageIdentifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identifier.ImageDigest == nil || *identifier.ImageDigest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %v", identifier.ImageDigest)
	}
	if identifier.ImageTag != nil {
		t.Errorf("expected nil tag, got %v", *identifier.ImageTag)
	}
}

func TestToImageIdentifier_TagOnly(t *testing.T) {
	id := ImageId{digest: "", tag: "latest"}
	identifier, err := id.ToImageIdentifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identifier.ImageDigest != nil {
		t.Errorf("expected nil digest, got %v", *identifier.ImageDigest)
	}
	if identifier.ImageTag == nil || *identifier.ImageTag != "latest" {
		t.Errorf("expected tag latest, got %v", identifier.ImageTag)
	}
}

func TestToImageIdentifier_BothEmpty(t *testing.T) {
	id := ImageId{digest: "", tag: ""}
	_, err := id.ToImageIdentifier()
	if err == nil {
		t.Fatal("expected error when both digest and tag are empty, got nil")
	}
}

// buildPushStream creates a Docker push stream with status messages and an optional Aux message.
func buildPushStream(t *testing.T, includeAux bool, digest string, tag string) bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)

	// Simulate typical push status messages
	statusMessages := []jsonmessage.JSONMessage{
		{Status: "Pushing layer"},
		{Status: "Pushed"},
	}
	for _, msg := range statusMessages {
		if err := encoder.Encode(msg); err != nil {
			t.Fatalf("failed to encode status message: %v", err)
		}
	}

	if includeAux {
		pushResult := dockerTypes.PushResult{Digest: digest, Tag: tag}
		auxBytes, err := json.Marshal(pushResult)
		if err != nil {
			t.Fatalf("failed to marshal push result: %v", err)
		}
		raw := json.RawMessage(auxBytes)
		auxMsg := jsonmessage.JSONMessage{Aux: &raw}
		if err := encoder.Encode(auxMsg); err != nil {
			t.Fatalf("failed to encode aux message: %v", err)
		}
	}

	return buf
}

func TestGetImageIdFromDockerDaemonJsonMessages_WithAux(t *testing.T) {
	buf := buildPushStream(t, true, "sha256:abcdef1234567890", "v1.0")
	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "sha256:abcdef1234567890" {
		t.Errorf("expected digest sha256:abcdef1234567890, got %s", result.digest)
	}
	if result.tag != "v1.0" {
		t.Errorf("expected tag v1.0, got %s", result.tag)
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_WithoutAux(t *testing.T) {
	buf := buildPushStream(t, false, "", "")
	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "" {
		t.Errorf("expected empty digest, got %s", result.digest)
	}
	if result.tag != "" {
		t.Errorf("expected empty tag, got %s", result.tag)
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_AuxWithEmptyDigest(t *testing.T) {
	buf := buildPushStream(t, true, "", "v1.0")
	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "" {
		t.Errorf("expected empty digest, got %s", result.digest)
	}
	if result.tag != "v1.0" {
		t.Errorf("expected tag v1.0, got %s", result.tag)
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_AuxWithEmptyTag(t *testing.T) {
	buf := buildPushStream(t, true, "sha256:abcdef1234567890", "")
	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "sha256:abcdef1234567890" {
		t.Errorf("expected digest sha256:abcdef1234567890, got %s", result.digest)
	}
	if result.tag != "" {
		t.Errorf("expected empty tag, got %s", result.tag)
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_EmptyStream(t *testing.T) {
	buf := bytes.Buffer{}
	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "" || result.tag != "" {
		t.Errorf("expected empty ImageId from empty stream, got digest=%q tag=%q", result.digest, result.tag)
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_ErrorInStream(t *testing.T) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	errMsg := jsonmessage.JSONMessage{
		Error: &jsonmessage.JSONError{
			Code:    500,
			Message: "push failed",
		},
	}
	if err := encoder.Encode(errMsg); err != nil {
		t.Fatalf("failed to encode error message: %v", err)
	}

	_, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err == nil {
		t.Fatal("expected error from stream with error message, got nil")
	}
}

func TestGetImageIdFromDockerDaemonJsonMessages_MultipleAuxMessages(t *testing.T) {
	// When multiple Aux messages are present, the last one should win
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)

	// First Aux message
	pushResult1 := dockerTypes.PushResult{Digest: "sha256:first", Tag: "tag1"}
	auxBytes1, _ := json.Marshal(pushResult1)
	raw1 := json.RawMessage(auxBytes1)
	if err := encoder.Encode(jsonmessage.JSONMessage{Aux: &raw1}); err != nil {
		t.Fatalf("failed to encode first aux: %v", err)
	}

	// Second Aux message (should overwrite)
	pushResult2 := dockerTypes.PushResult{Digest: "sha256:second", Tag: "tag2"}
	auxBytes2, _ := json.Marshal(pushResult2)
	raw2 := json.RawMessage(auxBytes2)
	if err := encoder.Encode(jsonmessage.JSONMessage{Aux: &raw2}); err != nil {
		t.Fatalf("failed to encode second aux: %v", err)
	}

	result, err := getImageIdFromDockerDaemonJsonMessages(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.digest != "sha256:second" {
		t.Errorf("expected last digest sha256:second, got %s", result.digest)
	}
	if result.tag != "tag2" {
		t.Errorf("expected last tag tag2, got %s", result.tag)
	}
}
