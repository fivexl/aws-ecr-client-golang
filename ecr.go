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

func newUnsupportedImageFinding(description string) []types.ImageScanFinding {
	return []types.ImageScanFinding{{
		Name:        aws.String("ECR_ERROR_UNSUPPORTED_IMAGE"),
		Description: aws.String(description),
		Severity:    types.FindingSeverityInformational,
	}}
}

func GetImageScanResults(client *ecr.Client, imageId ImageId, ecrRepoName string, timeout time.Duration) ([]types.ImageScanFinding, error) {
	input := ecr.DescribeImageScanFindingsInput{
		ImageId: &types.ImageIdentifier{
			ImageDigest: &imageId.digest,
			ImageTag:    &imageId.tag,
		},
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
		output, waiterErr = w.WaitForOutput(context.TODO(), &input, timeout)
		if waiterErr == nil {
			break
		}
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
		// Handle unsupported images with Clair-based scanning: DescribeImageScanFindings
		// returns ScanStatusFailed with "UnsupportedImageError" in the description instead
		// of ScanStatusUnsupportedImage. That causes WaitForOutput to return the error.
		// So here we have to check the status description for "UnsupportedImageError" separately.
		failedOutput, describeErr := client.DescribeImageScanFindings(context.TODO(), &input)
		if describeErr != nil {
			return nil, fmt.Errorf("waiting for scan failed: %w, and describing findings also failed: %w", waiterErr, describeErr)
		}
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
