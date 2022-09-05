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

	"github.com/distribution/distribution/reference"
	"github.com/urfave/cli/v2"
)

// VERSION - will  be set up via -ldflags
var VERSION string

func main() {

	var stageRepo string
	var images string
	var cveLevelsIgnoreListString string
	var cveIgnoreListString string
	var junitPath string
	var scanWaitTimeout int
	var skipPush bool

	app := &cli.App{
		Usage: "AWS ECR client to automated push to ECR and handling of vulnerability.\nVersion " + VERSION,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "images",
				Aliases:     []string{"i"},
				Usage:       "Space-separated list of full image references to push.",
				EnvVars:     []string{"AWS_ECR_CLIENT_IMAGES"},
				Destination: &images,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "stage-ecr-repo",
				Aliases:     []string{"s"},
				Value:       "",
				DefaultText: "empty string",
				Usage:       "AWS ECR Repository where the image will be sent for scanning before pushing it to destination repo with the tag ecs-client-scan-<timestamp>. If omitted, then the repo of the first wiven image will be used.",
				EnvVars:     []string{"AWS_ECR_CLIENT_STAGE_ECR_REPO"},
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
			&cli.IntFlag{
				Name:        "scan-wait-timeout",
				Value:       20,
				DefaultText: "20",
				Usage:       "The max duration (in minutes) to wait for the image scan to complete. If exceeded, the operation will fail and the tag will not be pushed.",
				EnvVars:     []string{"AWS_ECR_CLIENT_SCAN_WAIT_TIMEOUT"},
				Destination: &scanWaitTimeout,
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

	cli.AppHelpTemplate = fmt.Sprintf("%sFind source code, usage examples, report issues, get support: https://github.com/fivexl/aws-ecr-client-golang\n", cli.AppHelpTemplate)

	app.Action = func(c *cli.Context) error {

		fmt.Printf("aws-ecr-client, version %s\n", VERSION)

		_, err := AreSeverityLevelsValid(cveLevelsIgnoreListString)
		if err != nil {
			return err
		}

		cveLevelsIgnoreList := dedupList(strings.Fields(cveLevelsIgnoreListString))
		cveIgnoreList := dedupList(strings.Fields(cveIgnoreListString))
		imageList := dedupList(strings.Fields(images))

		// -----------------------------------
		// Push to STAGE repo
		// -----------------------------------

		if stageRepo == "" {
			fmt.Println("Note: Stage repo is not specified - will use the the repo of the first given image as a scanning silo")
			stageRepo = imageList[0]
		}

		stageRepoNamed, err := GetECRRepo(stageRepo)
		if err != nil {
			return err
		}

		now := time.Now()
		dockerTagRe := regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
		// Sanitize tag name and replace all unwanted symbols to -
		tagForScanning := dockerTagRe.ReplaceAllString("ecs-client-scan-"+fmt.Sprint(now.Unix()), "-")
		stageImageRef, err := reference.WithTag(stageRepoNamed, tagForScanning)
		if err != nil {
			return err
		}

		fmt.Printf("Push image to the scanning repo as %s\n", stageImageRef.String())
		if err = Tag(imageList[0], stageImageRef.String()); err != nil {
			return err
		}
		imageId, err := Push(stageImageRef.String())
		if err != nil {
			return err
		}

		fmt.Printf("Checking scan result for the image %s\n", stageImageRef.String())
		client, err := GetECRClient()
		if err != nil {
			return err
		}
		// Get the ECR repo name without the domain part, like: `some/repo/name`
		stageRepoPath := reference.Path(stageRepoNamed)
		timeout := time.Duration(scanWaitTimeout) * time.Minute
		findings, err := GetImageScanResults(client, imageId, stageRepoPath, timeout)
		if err != nil {
			return err
		}

		PrintFindings(findings, cveLevelsIgnoreList, cveIgnoreList)

		if junitPath != "" {
			fmt.Printf("Writing junit report to: %s\n", junitPath)
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
			return fmt.Errorf("there are CVEs found! Please, fix them first. Will not proceed with pushing to the destination registries")
		}

		if skipPush {
			fmt.Printf("Skip push to destination repo because of --skip-push flag or AWS_ECR_CLIENT_SKIP_PUSH env variable\n")
			return nil
		}

		for _, ref := range imageList {
			fmt.Printf("Pushing: %s\n", ref)
			_, err = Push(ref)
			if err != nil {
				return err
			}
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
