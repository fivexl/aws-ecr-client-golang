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
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

// VERSION - will  be set up via -ldflags
var VERSION string

func main() {

	var tag string
	var additionalTags string
	var stageRepo string
	var destinationRepo string
	var cveLevelsIgnoreListString string
	var cveIgnoreListString string
	var junitPath string
	var skipPush bool

	app := &cli.App{
		Usage: "AWS ECR client to automated push to ECR and handling of vulnerability.\nVersion " + VERSION,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "destination-repo",
				Aliases:     []string{"d"},
				Usage:       "Final destination of the image",
				EnvVars:     []string{"AWS_ECR_CLIENT_DESTINATION_REPO"},
				Destination: &destinationRepo,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "tag",
				Aliases:     []string{"t"},
				Usage:       "Image tag to push. Tag should already exist.",
				EnvVars:     []string{"AWS_ECR_CLIENT_IMAGE_TAG"},
				Destination: &tag,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "additional-tags",
				Aliases:     []string{"a"},
				Value:       "latest",
				DefaultText: "latest",
				Usage:       "Space-separated list of tags to add to the image and push.",
				EnvVars:     []string{"AWS_ECR_CLIENT_ADDITIONAL_TAGS"},
				Destination: &additionalTags,
			},
			&cli.StringFlag{
				Name:        "stage-repo",
				Aliases:     []string{"s"},
				Value:       "",
				DefaultText: "empty string",
				Usage:       "Repository where image will be sent for scanning before pushing it to destination repo with the tag <destination-repo-name>-<tag>-scan-<timestamp>. Will push directly to destination repo with the specified tag if no value provided",
				EnvVars:     []string{"AWS_ECR_CLIENT_STAGE_REPO"},
				Destination: &stageRepo,
			},
			&cli.StringFlag{
				Name:        "ignore-levels",
				Aliases:     []string{"l"},
				Value:       "",
				DefaultText: "empty string",
				Usage:       "Space-separated list of CVE severity levels to ignore. Valid severity levels are: " + GetFindingSeverityLevelsAsString(),
				EnvVars:     []string{"AWS_ECR_CLIENT_IGNORE_CVE_LEVEL"},
				Destination: &cveLevelsIgnoreListString,
			},
			&cli.StringFlag{
				Name:        "ignore-cve",
				Aliases:     []string{"c"},
				Value:       "",
				DefaultText: "empty string",
				Usage:       "Space-separated list of individual CVE's to ignore.",
				EnvVars:     []string{"AWS_ECR_CLIENT_IGNORE_CVE"},
				Destination: &cveIgnoreListString,
			},
			&cli.StringFlag{
				Name:        "junit-report-path",
				Aliases:     []string{"j"},
				Value:       "",
				DefaultText: "",
				Usage:       "If set then CVE scan result will be written in JUNIT format to the path provided as a value. Useful for CI (like Jenkins) to keep ignored CVE visible",
				EnvVars:     []string{"AWS_ECR_CLIENT_JUNIT_REPORT_PATH"},
				Destination: &junitPath,
			},
			&cli.BoolFlag{
				Name:        "skip-push",
				Aliases:     []string{"p"},
				Value:       false,
				DefaultText: "false",
				Usage:       "Only push to scanning silo and do not push to destination repo even if there are no CVE's (useful for CI).",
				EnvVars:     []string{"AWS_ECR_CLIENT_SKIP_PUSH"},
				Destination: &skipPush,
			},
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`%s

	Find source code, usage examples, report issues, get support: https://github.com/fivexl/aws-ecr-client-golang
	
	`, cli.AppHelpTemplate)

	app.Action = func(c *cli.Context) error {

		fmt.Printf("\naws-ecr-client, version %s\n", VERSION)

		_, err := AreSeverityLevelsValid(cveLevelsIgnoreListString)
		if err != nil {
			return err
		}

		cveLevelsIgnoreList := dedupList(strings.Fields(cveLevelsIgnoreListString))
		cveIgnoreList := dedupList(strings.Fields(cveIgnoreListString))

		if stageRepo == "" {
			fmt.Printf("\nNote: Stage repo is not specified - will use destination repo as scanning silo\n")
			stageRepo = destinationRepo
		}

		repoName, err := GetRepoName(destinationRepo)
		if err != nil {
			return err
		}

		now := time.Now()
		dockerTagRe := regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
		// Sanitize tag name and replace all unwanted symbols to -
		tagForScanning := dockerTagRe.ReplaceAllString(repoName+"-"+tag+"-scan-"+fmt.Sprint(now.Unix()), "-")

		fmt.Printf("\nFirst push image to scanning repo as %s:%s\n", stageRepo, tagForScanning)
		err = Tag(destinationRepo+":"+tag, stageRepo+":"+tagForScanning)
		if err != nil {
			return err
		}

		imageId, err := Push(stageRepo, tagForScanning)
		if err != nil {
			return err
		}

		fmt.Printf("\nChecking scan result for the image %s:%s\n", stageRepo, tagForScanning)
		client, err := GetECRClient()
		if err != nil {
			return err
		}
		findings, err := GetImageScanResults(client, imageId, stageRepo)
		if err != nil {
			return err
		}

		PrintFindings(findings, cveLevelsIgnoreList, cveIgnoreList)

		if junitPath != "" {
			fmt.Printf("\nWriting junit report to: %s\n", junitPath)
			junitFile, err := os.OpenFile(junitPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
			if err != nil {
				return err
			}
			defer junitFile.Close()
			err = WriteJunitReport(findings, junitFile)
			if err != nil {
				return err
			}
		}

		if len(findings) > 0 && len(findings) > len(GetIgnoredFindings(findings, cveLevelsIgnoreList, cveIgnoreList)) {
			return fmt.Errorf("\nThere are CVEs found. Fix them first. Will not proceed with pushing %s:%s\n", destinationRepo, tag)
		}

		if skipPush {
			fmt.Printf("\nSkip push to destination repo because of --skip-push flag or AWS_ECR_CLIENT_SKIP_PUSH env variable\n")
			return nil
		}

		fmt.Printf("\nPushing %s:%s\n", destinationRepo, tag)

		_, err = Push(destinationRepo, tag)
		if err != nil {
			return err
		}

		additionalTagsList := strings.Fields(additionalTags)
		if len(additionalTagsList) > 0 {
			fmt.Printf("\nPushing additional tags: %s\n", strings.Join(additionalTagsList, ", "))
			for _, additionalTag := range additionalTagsList {
				err = Tag(destinationRepo+":"+tag, destinationRepo+":"+additionalTag)
				if err != nil {
					return err
				}

				_, err = Push(destinationRepo, additionalTag)
				if err != nil {
					return err
				}
				fmt.Printf("\n")
			}
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("\nDone\n")
}
