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
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/jstemmer/go-junit-report/formatter"
	"github.com/jstemmer/go-junit-report/parser"
)

func WriteJunitReport(findings []types.ImageScanFinding, output io.Writer) error {

	sortedFindings := SortFindingsBySerityLevel(findings)

	testPackage := parser.Package{
		Name:        "Container Image CVE scan",
		Duration:    time.Duration(len(GetFindingSeverityLevelsAsList())) * time.Second,
		CoveragePct: "100",
		Time:        0,
	}

	for _, severity := range GetFindingSeverityLevelsAsList() {
		result := parser.PASS
		output := []string{}
		if len(sortedFindings[severity]) > 0 {
			result = parser.FAIL
			for _, finding := range sortedFindings[severity] {
				output = append(output, *finding.Name)
			}
		}
		test := parser.Test{
			Name:     severity,
			Duration: time.Duration(1) * time.Second,
			Result:   result,
			Output:   output,
		}
		testPackage.Tests = append(testPackage.Tests, &test)
	}

	report := parser.Report{}
	report.Packages = []parser.Package{testPackage}

	// Write xml
	return formatter.JUnitReportXML(&report, false, "", output)
}
