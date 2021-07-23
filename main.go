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
	"time"

	"github.com/urfave/cli/v2"
)

// VERSION - will  be set up via -ldflags
var VERSION string

func main() {

	var tag string
	var stageRepo string
	var destinationRepo string
	var cveLevelsIgnoreList string
	var cveIgnoreList string
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
				Usage:       "Image tag to push",
				EnvVars:     []string{"AWS_ECR_CLIENT_IMAGE_TAG"},
				Destination: &tag,
				Required:    true,
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
				Destination: &cveLevelsIgnoreList,
			},
			&cli.StringFlag{
				Name:        "ignore-cve",
				Aliases:     []string{"c"},
				Value:       "",
				DefaultText: "empty string",
				Usage:       "Space-separated list of individual CVE's to ignore.",
				EnvVars:     []string{"AWS_ECR_CLIENT_IGNORE_CVE"},
				Destination: &cveIgnoreList,
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
		_, err := AreSeverityLevelsValid(cveLevelsIgnoreList)
		if err != nil {
			return err
		}

		if stageRepo == "" {
			fmt.Printf("\nNote: Stage repo is not specified - will use destination repo as scanning silo\n")
			stageRepo = destinationRepo
		}

		repoName := GetRepoName(destinationRepo)
		now := time.Now()
		tagForScanning := repoName + "-" + tag + "-scan-" + fmt.Sprint(now.Unix())

		fmt.Printf("\nFirst push image to scanning repo %s with the tag %s\n\n", stageRepo, tagForScanning)
		err = Tag(destinationRepo, tag, tagForScanning)
		if err != nil {
			return err
		}

		imageId, err := Push(stageRepo, tagForScanning)
		if err != nil {
			return err
		}

		fmt.Printf("\nChecking scan result for the image %s:%s\n\n", stageRepo, tagForScanning)
		isScanFailed, err := IsScanFailed(stageRepo, imageId, cveLevelsIgnoreList, cveIgnoreList)
		if err != nil {
			return err
		}

		if isScanFailed {
			return fmt.Errorf("There are CVEs found. Fix them first. Will not proceed with pushing %s:%s\n", destinationRepo, tag)
		}

		if skipPush {
			fmt.Printf("Skip push to destination repo because of --skip-push flag or AWS_ECR_CLIENT_SKIP_PUSH env variable\n")
			return nil
		}

		fmt.Printf("\nPushing %s:%s\n\n", destinationRepo, tag)

		_, err = Push(destinationRepo, tag)
		if err != nil {
			return err
		}

		fmt.Printf("\nPushing %s:%s\n\n", destinationRepo, "latest")
		err = Tag(destinationRepo, tag, "latest")
		if err != nil {
			return err
		}

		_, err = Push(destinationRepo, "latest")
		if err != nil {
			return err
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
