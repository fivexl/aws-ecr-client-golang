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
	"io"

	dockerTypes "github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
)

type ImageId struct {
	digest string
	tag    string
}

func getDockerClient() (*dockerClient.Client, error) {
	return dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
}

func imagePush(client *dockerClient.Client, authConfig dockerTypes.AuthConfig, imageRef string) (ImageId, error) {

	authConfigBytes, _ := json.Marshal(authConfig)
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

	opts := dockerTypes.ImagePushOptions{RegistryAuth: authConfigEncoded}
	rd, err := client.ImagePush(context.Background(), imageRef, opts)
	if err != nil {
		return ImageId{}, err
	}
	defer rd.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rd)
	if err != nil {
		return ImageId{}, err
	}

	return getImageIdFromDockerDaemonJsonMessages(*buf)
}

func imageTag(client *dockerClient.Client, imageId string, newImageId string) error {

	err := client.ImageTag(context.Background(), imageId, newImageId)
	if err != nil {
		return err
	}

	return nil
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
			return result, err
		}
		if jsonMessage.Aux != nil {
			var r dockerTypes.PushResult
			if err := json.Unmarshal(*jsonMessage.Aux, &r); err != nil {
				return result, err
			} else {
				result.tag = r.Tag
				result.digest = r.Digest
			}
		}
	}
	return result, nil
}
