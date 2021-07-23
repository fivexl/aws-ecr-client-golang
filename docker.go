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
	"time"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
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

func imagePush(dockerClient *client.Client, authConfig dockerTypes.AuthConfig, repo string, tag string) (ImageId, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	authConfigBytes, _ := json.Marshal(authConfig)
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

	target := repo + ":" + tag
	opts := dockerTypes.ImagePushOptions{RegistryAuth: authConfigEncoded}
	rd, err := dockerClient.ImagePush(ctx, target, opts)
	if err != nil {
		return ImageId{}, err
	}
	defer rd.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rd)
	if err != nil {
		return ImageId{}, err
	}

	err = printDockerDaemonJsonMessages(*buf, "docker-push")
	if err != nil {
		return ImageId{}, err
	}

	return getImageIdFromDockerDaemonJsonMessages(*buf)
}

func imageTag(dockerClient *client.Client, repo string, imageId string, destinationTag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	err := dockerClient.ImageTag(ctx, repo+":"+imageId, repo+":"+destinationTag)
	if err != nil {
		return err
	}

	return nil
}

func printDockerDaemonJsonMessages(message bytes.Buffer, prefix string) error {
	decoder := json.NewDecoder(&message)
	for {
		var jsonMessage jsonmessage.JSONMessage
		if err := decoder.Decode(&jsonMessage); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := jsonMessage.Error; err != nil {
			return err
		}
		if jsonMessage.Status != "" {
			fmt.Printf("%s: %s\n", prefix, jsonMessage.Status)
		}
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
