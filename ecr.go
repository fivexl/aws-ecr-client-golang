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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/distribution/reference"
	dockerRegistry "github.com/docker/docker/api/types/registry"
	"github.com/olekukonko/tablewriter"
)

func GetFindingSeverityLevelsAsList() []string {
	return []string{
		string(types.FindingSeverityCritical),
		string(types.FindingSeverityHigh),
		string(types.FindingSeverityMedium),
		string(types.FindingSeverityLow),
		string(types.FindingSeverityInformational),
		string(types.FindingSeverityUndefined),
	}
}

func GetFindingSeverityLevelsAsString() string {
	return strings.Join(GetFindingSeverityLevelsAsList(), ", ")
}

func SortFindingsBySerityLevel(findings []types.ImageScanFinding) map[string][]types.ImageScanFinding {
	result := map[string][]types.ImageScanFinding{}

	for _, severity := range GetFindingSeverityLevelsAsList() {
		result[severity] = []types.ImageScanFinding{}
	}

	for _, finding := range findings {
		result[string(finding.Severity)] = append(result[string(finding.Severity)], finding)
	}
	return result
}

func GetIgnoredFindings(findings []types.ImageScanFinding, severityLevelsToIgnore []string, cveToIgnore []string) []types.ImageScanFinding {
	result := []types.ImageScanFinding{}

	for _, finding := range findings {
		if isIgnored, _ := IsFindingIgnored(finding, severityLevelsToIgnore, cveToIgnore); isIgnored {
			result = append(result, finding)
		}
	}

	// A little bit of self check
	if len(findings) < len(result) {
		panic("Somehow number of ignored findings is more than total number of findings and it indicates internal logic error. Please report to mantainers")
	}

	return result
}

func IsFindingIgnored(finding types.ImageScanFinding, severityLevelsToIgnore []string, cveToIgnore []string) (bool, string) {
	if slices.Contains(severityLevelsToIgnore, string(finding.Severity)) {
		return true, "Ignored severyity level"
	}
	if finding.Name != nil && slices.Contains(cveToIgnore, *finding.Name) {
		return true, "Ignored individual CVE"
	}
	return false, ""
}

func AreSeverityLevelsValid(levels string) (bool, error) {
	validLevels := GetFindingSeverityLevelsAsList()
	for _, level := range strings.Fields(levels) {
		if !slices.Contains(validLevels, level) {
			return false, fmt.Errorf("%s is not a valid finding severity level. Valid levels are: %s", level, GetFindingSeverityLevelsAsString())
		}
	}
	return true, nil
}

func GetECRClient() (*ecr.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	return ecr.NewFromConfig(cfg), nil
}

func getAuthorizationToken(client *ecr.Client) ([]types.AuthorizationData, error) {
	input := &ecr.GetAuthorizationTokenInput{}
	output, err := client.GetAuthorizationToken(context.TODO(), input)
	if err != nil {
		return nil, err
	}
	return output.AuthorizationData, nil
}

func GetDockerAuthConfig(client *ecr.Client) (dockerRegistry.AuthConfig, error) {
	authTokens, err := getAuthorizationToken(client)
	if err != nil {
		return dockerRegistry.AuthConfig{}, err
	}
	// TODO: find token for the correct repo based on its url
	if len(authTokens) != 1 {
		return dockerRegistry.AuthConfig{}, fmt.Errorf("received %d auth tokens but expected one. Not sure what to do", len(authTokens))
	}
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ecr/types#AuthorizationData
	// AuthorizationToken *string
	// A base64-encoded string that contains authorization data for the specified
	// Amazon ECR registry. When the string is decoded, it is presented in the format
	// user:password for private registry authentication using docker login.
	decodedToken, err := base64.StdEncoding.DecodeString(*authTokens[0].AuthorizationToken)
	if err != nil {
		return dockerRegistry.AuthConfig{}, err
	}
	usernamePassword := strings.Split(string(decodedToken), ":")
	if len(usernamePassword) != 2 {
		return dockerRegistry.AuthConfig{}, fmt.Errorf("received %s as auth token but expected username:password", string(decodedToken))
	}

	return dockerRegistry.AuthConfig{
		Username:      usernamePassword[0],
		Password:      usernamePassword[1],
		ServerAddress: *authTokens[0].ProxyEndpoint,
	}, nil
}

func GetECRRepo(registryName string) (reference.Named, error) {
	reg, err := reference.ParseNamed(registryName)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(reference.Domain(reg), "amazonaws.com") {
		return nil, fmt.Errorf("unexpected ECR registry name %s. Expected format: AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/myrepo/name", registryName)
	}
	return reg, nil
}

// Media types for manifest lists / OCI image indexes.
const (
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIImageIndex      = "application/vnd.oci.image.index.v1+json"
)

// manifestPlatform represents the platform section of a manifest entry.
type manifestPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// manifestEntry represents a single manifest in a manifest list or OCI image index.
type manifestEntry struct {
	MediaType string           `json:"mediaType"`
	Digest    string           `json:"digest"`
	Size      int              `json:"size"`
	Platform  manifestPlatform `json:"platform"`
}

// manifestIndex represents a Docker manifest list or OCI image index.
type manifestIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []manifestEntry `json:"manifests"`
}

// selectPlatformDigest picks the best platform image digest from a manifest list JSON.
// It prefers linux/amd64, then any linux image, then the first manifest with a known OS.
// Returns the digest of the selected platform image, or an error if the manifest list
// is empty or cannot be parsed.
func selectPlatformDigest(manifestJSON string) (string, string, string, error) {
	var ml manifestIndex
	if err := json.Unmarshal([]byte(manifestJSON), &ml); err != nil {
		return "", "", "", fmt.Errorf("failed to parse manifest list: %w", err)
	}

	if len(ml.Manifests) == 0 {
		return "", "", "", fmt.Errorf("manifest list is empty, no platform images to scan")
	}

	// Prefer linux/amd64
	for _, m := range ml.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			return m.Digest, m.Platform.OS, m.Platform.Architecture, nil
		}
	}

	// Fallback: first linux image of any architecture
	for _, m := range ml.Manifests {
		if m.Platform.OS == "linux" {
			return m.Digest, m.Platform.OS, m.Platform.Architecture, nil
		}
	}

	// Fallback: first manifest with a known OS (skip attestation manifests etc.)
	for _, m := range ml.Manifests {
		if m.Platform.OS != "" && m.Platform.OS != "unknown" {
			return m.Digest, m.Platform.OS, m.Platform.Architecture, nil
		}
	}

	// Last resort: use the first manifest
	m := ml.Manifests[0]
	return m.Digest, m.Platform.OS, m.Platform.Architecture, nil
}

// ResolveImageIndexDigest checks if the given image is a manifest list / OCI image index.
// If it is, it returns an ImageId with the digest of a platform-specific image suitable
// for scanning (preferring linux/amd64). If it's not an index or the check fails,
// returns the original ImageId unchanged.
func ResolveImageIndexDigest(client *ecr.Client, imageId ImageId, repoName string) (ImageId, error) {
	imageIdentifier, err := imageId.ToImageIdentifier()
	if err != nil {
		debugf("ResolveImageIndexDigest: cannot build identifier: %v", err)
		return imageId, nil
	}

	// Request manifest lists and regular manifests so we get whatever type the image is
	acceptedMediaTypes := []string{
		mediaTypeDockerManifestList,
		mediaTypeOCIImageIndex,
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}

	input := &ecr.BatchGetImageInput{
		RepositoryName:     &repoName,
		ImageIds:           []types.ImageIdentifier{*imageIdentifier},
		AcceptedMediaTypes: acceptedMediaTypes,
	}

	debugf("ResolveImageIndexDigest: calling BatchGetImage for repo=%q", repoName)
	output, err := client.BatchGetImage(context.TODO(), input)
	if err != nil {
		debugf("ResolveImageIndexDigest: BatchGetImage failed: %v", err)
		return imageId, nil
	}

	if len(output.Images) == 0 {
		debugf("ResolveImageIndexDigest: BatchGetImage returned no images")
		return imageId, nil
	}

	image := output.Images[0]
	if image.ImageManifestMediaType == nil || image.ImageManifest == nil {
		debugf("ResolveImageIndexDigest: image has no manifest media type or manifest content")
		return imageId, nil
	}

	mediaType := *image.ImageManifestMediaType
	debugf("ResolveImageIndexDigest: manifest media type is %s", mediaType)

	if mediaType != mediaTypeDockerManifestList && mediaType != mediaTypeOCIImageIndex {
		debugf("ResolveImageIndexDigest: not a manifest list/image index, using original ImageId")
		return imageId, nil
	}

	// It's a manifest list / image index - resolve to a platform image
	digest, os, arch, err := selectPlatformDigest(*image.ImageManifest)
	if err != nil {
		return imageId, fmt.Errorf("image is a manifest list but failed to select platform image: %w", err)
	}

	fmt.Printf("Image is a manifest list/image index (%s), resolved to platform image %s/%s (digest: %s) for scanning\n",
		mediaType, os, arch, digest)

	return ImageId{
		digest: digest,
		tag:    "", // Platform images in a manifest list are referenced by digest, not tag
	}, nil
}

func newUnsupportedImageFinding(description string) []types.ImageScanFinding {
	return []types.ImageScanFinding{{
		Name:        aws.String("ECR_ERROR_UNSUPPORTED_IMAGE"),
		Description: aws.String(description),
		Severity:    types.FindingSeverityInformational,
	}}
}

func GetImageScanResults(client *ecr.Client, imageId ImageId, ecrRepoName string, timeout time.Duration) ([]types.ImageScanFinding, error) {
	imageIdentifier, err := imageId.ToImageIdentifier()
	if err != nil {
		return nil, fmt.Errorf("cannot query scan results: %w", err)
	}
	digestStr := "<nil>"
	if imageIdentifier.ImageDigest != nil {
		digestStr = *imageIdentifier.ImageDigest
	}
	tagStr := "<nil>"
	if imageIdentifier.ImageTag != nil {
		tagStr = *imageIdentifier.ImageTag
	}
	debugf("GetImageScanResults: repo=%q imageDigest=%q imageTag=%q timeout=%s", ecrRepoName, digestStr, tagStr, timeout)
	input := ecr.DescribeImageScanFindingsInput{
		ImageId:        imageIdentifier,
		RepositoryName: &ecrRepoName,
	}

	var findings []types.ImageScanFinding

	// With AWS native basic scanning, there can be a delay between pushing an image
	// and the scan becoming available. The ImageScanCompleteWaiter treats
	// ScanNotFoundException as a terminal error instead of retrying. We handle this
	// by retrying the waiter when we get ScanNotFoundException, up to the overall timeout.
	const scanInitRetryInterval = 15 * time.Second
	const maxScanInitRetries = 20 // up to 5 minutes of waiting for scan to be initiated
	var output *ecr.DescribeImageScanFindingsOutput

	w := ecr.NewImageScanCompleteWaiter(client)

	var waiterErr error
	for attempt := 0; attempt <= maxScanInitRetries; attempt++ {
		debugf("WaitForOutput attempt %d/%d", attempt+1, maxScanInitRetries+1)
		output, waiterErr = w.WaitForOutput(context.TODO(), &input, timeout)
		if waiterErr == nil {
			debugf("WaitForOutput succeeded")
			break
		}
		debugf("WaitForOutput error: %v (type: %T)", waiterErr, waiterErr)
		// Check if the waiter failed because the scan doesn't exist yet
		var scanNotFound *types.ScanNotFoundException
		if errors.As(waiterErr, &scanNotFound) {
			if attempt < maxScanInitRetries {
				fmt.Printf("Scan not yet initiated, retrying in %s (attempt %d/%d)...\n",
					scanInitRetryInterval, attempt+1, maxScanInitRetries)
				time.Sleep(scanInitRetryInterval)
				continue
			}
			// Exhausted retries - treat as unsupported image
			return newUnsupportedImageFinding("Image scan does not exist - image is not supported for scanning"), nil
		}
		// For non-ScanNotFound errors, fall through to legacy error handling
		break
	}

	if waiterErr != nil {
		debugf("Waiter failed, attempting fallback DescribeImageScanFindings")
		// Handle unsupported images with Clair-based scanning: DescribeImageScanFindings
		// returns ScanStatusFailed with "UnsupportedImageError" in the description instead
		// of ScanStatusUnsupportedImage. That causes WaitForOutput to return the error.
		// So here we have to check the status description for "UnsupportedImageError" separately.
		failedOutput, describeErr := client.DescribeImageScanFindings(context.TODO(), &input)
		if describeErr != nil {
			debugf("Fallback DescribeImageScanFindings also failed: %v", describeErr)
			return nil, fmt.Errorf("waiting for scan failed: %w, and describing findings also failed: %w", waiterErr, describeErr)
		}
		debugf("Fallback DescribeImageScanFindings status=%q description=%v",
			failedOutput.ImageScanStatus.Status, failedOutput.ImageScanStatus.Description)
		if failedOutput.ImageScanStatus.Status == types.ScanStatusFailed &&
			failedOutput.ImageScanStatus.Description != nil &&
			strings.Contains(*failedOutput.ImageScanStatus.Description, "UnsupportedImageError") {
			return newUnsupportedImageFinding(*failedOutput.ImageScanStatus.Description), nil
		}

		return nil, waiterErr
	}
	fmt.Printf("\nImage scan status: %s\n", output.ImageScanStatus.Status)
	findings = output.ImageScanFindings.Findings

	// Paginate through remaining results if there are more pages
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		paginatedOutput, paginateErr := client.DescribeImageScanFindings(context.TODO(), &input)
		if paginateErr != nil {
			return nil, paginateErr
		}
		findings = append(findings, paginatedOutput.ImageScanFindings.Findings...)
		output.NextToken = paginatedOutput.NextToken
	}

	return findings, nil
}

func PrintFindings(findings []types.ImageScanFinding, severityLevelsToIgnore []string, cveToIgnore []string) {

	ignoredFindings := []types.ImageScanFinding{}
	table := tablewriter.NewWriter(os.Stdout)

	table.Header("CVE", "Severity", "Ignored?", "Description", "URI")

	for _, finding := range findings {
		ignored := "No"
		name := ""
		description := ""
		uri := ""
		if finding.Name != nil {
			name = *finding.Name
		}
		if finding.Description != nil {
			description = *finding.Description
		}
		if finding.Uri != nil {
			uri = *finding.Uri
		}
		if isIgnored, reason := IsFindingIgnored(finding, severityLevelsToIgnore, cveToIgnore); isIgnored {
			ignoredFindings = append(ignoredFindings, finding)
			ignored = fmt.Sprintf("Yes (%s)", reason)
		}
		_ = table.Append(name, string(finding.Severity), ignored, description, uri)
	}

	fmt.Printf("\nFound the following CVEs\n")
	_ = table.Render()

	fmt.Printf("\nIgnored CVE severity levels: %s\n", strings.Join(severityLevelsToIgnore, ", "))
	fmt.Printf("Ignored CVE's:               %s\n\n", strings.Join(cveToIgnore, ", "))
	fmt.Print("Final scan result: ")

	if len(findings) > len(ignoredFindings) {
		fmt.Printf("Failed\n")
	} else {
		fmt.Printf("Passed\n")
	}
}
