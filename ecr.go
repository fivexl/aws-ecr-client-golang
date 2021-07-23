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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
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
		return dockerTypes.AuthConfig{}, fmt.Errorf("Received %d auth tokens but expected one. Not sure what to do", len(authTokens))
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
		return dockerTypes.AuthConfig{}, fmt.Errorf("Received %s as auth token but expected username:password", string(decodedToken))
	}

	return dockerTypes.AuthConfig{
		Username:      usernamePassword[0],
		Password:      usernamePassword[1],
		ServerAddress: *authTokens[0].ProxyEndpoint,
	}, nil
}

func GetRepoName(registryName string) string {
	repoSlised := strings.Split(string(registryName), "/")
	return repoSlised[len(repoSlised)-1]
}

// TODO: handle unsupported images like busybox or scratch that will fail the scan
func getImageScanResults(client *ecr.Client, imageId ImageId, repo string) ([]types.ImageScanFinding, error) {
	repoName := GetRepoName(repo)
	input := ecr.DescribeImageScanFindingsInput{
		ImageId: &types.ImageIdentifier{
			ImageDigest: &imageId.digest,
			ImageTag:    &imageId.tag,
		},
		RepositoryName: &repoName,
	}

	var findings []types.ImageScanFinding
	for {
		describeImageScanFindingsOutput, err := client.DescribeImageScanFindings(context.TODO(), &input)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Image scan status: %s\n", describeImageScanFindingsOutput.ImageScanStatus.Status)
		if describeImageScanFindingsOutput.ImageScanStatus.Status != types.ScanStatusInProgress {
			findings = describeImageScanFindingsOutput.ImageScanFindings.Findings
			break
		}
		time.Sleep(10 * time.Second)
	}

	return findings, nil

}

func AreThereCVEsToReport(client *ecr.Client, imageId ImageId, repo string, severityLevelsToIgnore []string, cveToIgnore []string) (bool, error) {

	findings, err := getImageScanResults(client, imageId, repo)
	if err != nil {
		return false, err
	}

	if len(findings) == 0 {
		fmt.Printf("No CVE's found. Good job!")
		return false, nil
	}

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
		for _, severityLevel := range severityLevelsToIgnore {
			if string(finding.Severity) == severityLevel {
				ignoredFindings = append(ignoredFindings, finding)
				ignored = "Yes (ignored severity level " + severityLevel + ")"
			}
		}
		for _, cve := range cveToIgnore {
			if string(name) == cve {
				ignoredFindings = append(ignoredFindings, finding)
				ignored = "Yes (ignored individual CVE)"
			}
		}

		table.Append([]string{name, string(finding.Severity), ignored, description, uri})
	}

	fmt.Printf("\nFound the following CVEs\n")
	table.Render()

	fmt.Printf("\nIgnored CVE severity levels: %s\n", strings.Join(severityLevelsToIgnore, " ,"))
	fmt.Printf("Ignored CVE's:               %s\n\n", strings.Join(cveToIgnore, " ,"))
	fmt.Print("Final scan result: ")

	if len(findings) > len(ignoredFindings) {
		fmt.Printf("Failed\n\n")
		return true, nil
	}

	fmt.Printf("Passed\n\n")

	return false, nil
}
