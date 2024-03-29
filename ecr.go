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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/distribution/distribution/reference"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/olekukonko/tablewriter"
)

func GetFindingSeverityLevelsAsList() []string {
	// TODO: is there a better way?
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
	for _, severityLevel := range severityLevelsToIgnore {
		if string(finding.Severity) == severityLevel {
			return true, "Ignored severyity level"
		}
	}
	for _, cve := range cveToIgnore {
		if finding.Name != nil && string(*finding.Name) == cve {
			return true, "Ignored individual CVE"
		}
	}
	return false, ""
}

// TODO: is there a better way?
func AreSeverityLevelsValid(levels string) (bool, error) {
	for _, level := range strings.Fields(levels) {
		isValid := false
		for _, validLevel := range GetFindingSeverityLevelsAsList() {
			if level == validLevel {
				isValid = true
			}
		}
		if !isValid {
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

	client := ecr.NewFromConfig(cfg)

	return client, nil
}

func getAuthorizationToken(client *ecr.Client) ([]types.AuthorizationData, error) {
	input := &ecr.GetAuthorizationTokenInput{}
	output, err := client.GetAuthorizationToken(context.TODO(), input)
	if err != nil {
		return nil, err
	}
	return output.AuthorizationData, nil
}

func GetDockerAuthConfig(client *ecr.Client) (dockerTypes.AuthConfig, error) {
	authTokens, err := getAuthorizationToken(client)
	if err != nil {
		return dockerTypes.AuthConfig{}, err
	}
	// TODO: find token for the correct repo based on its url
	if len(authTokens) != 1 {
		return dockerTypes.AuthConfig{}, fmt.Errorf("received %d auth tokens but expected one. Not sure what to do", len(authTokens))
	}
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ecr/types#AuthorizationData
	// AuthorizationToken *string
	// A base64-encoded string that contains authorization data for the specified
	// Amazon ECR registry. When the string is decoded, it is presented in the format
	// user:password for private registry authentication using docker login.
	decodedToken, err := base64.StdEncoding.DecodeString(*authTokens[0].AuthorizationToken)
	if err != nil {
		return dockerTypes.AuthConfig{}, err
	}
	usernamePassword := strings.Split(string(decodedToken), ":")
	if len(usernamePassword) != 2 {
		return dockerTypes.AuthConfig{}, fmt.Errorf("received %s as auth token but expected username:password", string(decodedToken))
	}

	return dockerTypes.AuthConfig{
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

func GetImageScanResults(client *ecr.Client, imageId ImageId, ecrRepoName string, timeout time.Duration) ([]types.ImageScanFinding, error) {
	input := ecr.DescribeImageScanFindingsInput{
		ImageId: &types.ImageIdentifier{
			ImageDigest: &imageId.digest,
			ImageTag:    &imageId.tag,
		},
		RepositoryName: &ecrRepoName,
	}

	var findings []types.ImageScanFinding

	w := ecr.NewImageScanCompleteWaiter(client)
	output, err := w.WaitForOutput(context.TODO(), &input, timeout)
	if err != nil {
		// Handle unsupported images.
		// In that case, by some reason, DescribeImageScanFindings returns `ScanStatusFailed`
		// instead of `ScanStatusUnsupportedImage`. That casues WaitForOutput to return the error.
		// So here we have to check the status description for "UnsupportedImageError" separately.
		failedOutput, err := client.DescribeImageScanFindings(context.TODO(), &input)
		if err != nil {
			return nil, err
		}
		if failedOutput.ImageScanStatus.Status == types.ScanStatusFailed &&
			strings.Contains(*failedOutput.ImageScanStatus.Description, "UnsupportedImageError") {
			findings = []types.ImageScanFinding{{
				Name:        aws.String("ECR_ERROR_UNSUPPORTED_IMAGE"),
				Description: failedOutput.ImageScanStatus.Description,
				Severity:    types.FindingSeverityInformational}}
			return findings, nil
		}

		return nil, err
	}
	fmt.Printf("\nImage scan status: %s\n", output.ImageScanStatus.Status)
	findings = output.ImageScanFindings.Findings

	return findings, nil
}

func PrintFindings(findings []types.ImageScanFinding, severityLevelsToIgnore []string, cveToIgnore []string) {

	ignoredFindings := []types.ImageScanFinding{}
	table := tablewriter.NewWriter(os.Stdout)

	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"CVE", "Severity", "Ignored?", "Description", "URI"})

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
		table.Append([]string{name, string(finding.Severity), ignored, description, uri})
	}

	fmt.Printf("\nFound the following CVEs\n")
	table.Render()

	fmt.Printf("\nIgnored CVE severity levels: %s\n", strings.Join(severityLevelsToIgnore, ", "))
	fmt.Printf("Ignored CVE's:               %s\n\n", strings.Join(cveToIgnore, ", "))
	fmt.Print("Final scan result: ")

	if len(findings) > len(ignoredFindings) {
		fmt.Printf("Failed\n")
	} else {
		fmt.Printf("Passed\n")
	}
}
