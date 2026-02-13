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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	dockerTypes "github.com/docker/docker/api/types"
	dockerImageTypes "github.com/docker/docker/api/types/image"
	dockerRegistry "github.com/docker/docker/api/types/registry"
	dockerClient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
)

type ImageId struct {
	digest string
	tag    string
}

// ToImageIdentifier converts ImageId to an ECR ImageIdentifier, using nil
// for empty fields to avoid sending empty strings that violate the ECR API
// parameter constraints (imageDigest must match '[a-zA-Z0-9-_+.]{0,20}:[a-fA-F0-9]{1,128}').
func (id ImageId) ToImageIdentifier() (*types.ImageIdentifier, error) {
	debugf("ToImageIdentifier: digest=%q (len=%d, bytes=%x) tag=%q", id.digest, len(id.digest), []byte(id.digest), id.tag)
	if id.digest == "" && id.tag == "" {
		return nil, fmt.Errorf("image identifier must have at least a digest or a tag, but both are empty")
	}
	identifier := &types.ImageIdentifier{}
	if id.digest != "" {
		identifier.ImageDigest = &id.digest
	}
	if id.tag != "" {
		identifier.ImageTag = &id.tag
	}
	return identifier, nil
}

func getDockerClient() (*dockerClient.Client, error) {
	return dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
}

func imagePush(client *dockerClient.Client, authConfig dockerRegistry.AuthConfig, imageRef string) (ImageId, error) {

	authConfigBytes, _ := json.Marshal(authConfig)
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

	opts := dockerImageTypes.PushOptions{RegistryAuth: authConfigEncoded}
	rd, err := client.ImagePush(context.Background(), imageRef, opts)
	if err != nil {
		return ImageId{}, err
	}
	defer func() { _ = rd.Close() }()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rd)
	if err != nil {
		return ImageId{}, err
	}

	debugf("Full Docker push stream for %s (%d bytes):\n%s", imageRef, buf.Len(), buf.String())

	return getImageIdFromDockerDaemonJsonMessages(*buf)
}

func imageTag(client *dockerClient.Client, imageId string, newImageId string) error {
	return client.ImageTag(context.Background(), imageId, newImageId)
}

func getImageIdFromDockerDaemonJsonMessages(message bytes.Buffer) (ImageId, error) {
	var result ImageId
	decoder := json.NewDecoder(&message)
	for {
		var jsonMessage jsonmessage.JSONMessage
		if err := decoder.Decode(&jsonMessage); err != nil {
			if err == io.EOF {
				break
			}
			return result, err
		}
		if err := jsonMessage.Error; err != nil {
			debugf("Push stream error message: %v", err)
			return result, err
		}
		if jsonMessage.Aux != nil {
			debugf("Push stream Aux raw JSON: %s", string(*jsonMessage.Aux))
			var r dockerTypes.PushResult
			if err := json.Unmarshal(*jsonMessage.Aux, &r); err != nil {
				return result, err
			}
			debugf("Push stream Aux parsed: digest=%q tag=%q size=%d", r.Digest, r.Tag, r.Size)
			result.tag = r.Tag
			result.digest = r.Digest
		}
	}
	debugf("Final ImageId from push stream: digest=%q (len=%d) tag=%q", result.digest, len(result.digest), result.tag)
	return result, nil
}
