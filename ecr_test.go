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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestGetFindingSeverityLevelsAsList(t *testing.T) {
	levels := GetFindingSeverityLevelsAsList()
	if len(levels) != 6 {
		t.Fatalf("expected 6 severity levels, got %d", len(levels))
	}
	expected := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED"}
	for i, level := range levels {
		if level != expected[i] {
			t.Errorf("expected level[%d] = %s, got %s", i, expected[i], level)
		}
	}
}

func TestAreSeverityLevelsValid_ValidLevels(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		valid  bool
		hasErr bool
	}{
		{"single valid", "HIGH", true, false},
		{"multiple valid", "HIGH MEDIUM LOW", true, false},
		{"all valid", "CRITICAL HIGH MEDIUM LOW INFORMATIONAL UNDEFINED", true, false},
		{"empty string", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := AreSeverityLevelsValid(tt.input)
			if valid != tt.valid {
				t.Errorf("expected valid=%v, got %v", tt.valid, valid)
			}
			if tt.hasErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.hasErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAreSeverityLevelsValid_InvalidLevels(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "high"},
		{"invalid level", "VERY_HIGH"},
		{"mixed valid and invalid", "HIGH INVALID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := AreSeverityLevelsValid(tt.input)
			if valid {
				t.Error("expected invalid, got valid")
			}
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestIsFindingIgnored_BySeverity(t *testing.T) {
	finding := types.ImageScanFinding{
		Name:     aws.String("CVE-2024-0001"),
		Severity: types.FindingSeverityHigh,
	}
	ignored, reason := IsFindingIgnored(finding, []string{"HIGH"}, []string{})
	if !ignored {
		t.Error("expected finding to be ignored by severity")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestIsFindingIgnored_ByCVE(t *testing.T) {
	finding := types.ImageScanFinding{
		Name:     aws.String("CVE-2024-0001"),
		Severity: types.FindingSeverityHigh,
	}
	ignored, reason := IsFindingIgnored(finding, []string{}, []string{"CVE-2024-0001"})
	if !ignored {
		t.Error("expected finding to be ignored by CVE name")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestIsFindingIgnored_NotIgnored(t *testing.T) {
	finding := types.ImageScanFinding{
		Name:     aws.String("CVE-2024-0001"),
		Severity: types.FindingSeverityHigh,
	}
	ignored, _ := IsFindingIgnored(finding, []string{"LOW"}, []string{"CVE-9999-9999"})
	if ignored {
		t.Error("expected finding to not be ignored")
	}
}

func TestIsFindingIgnored_NilName(t *testing.T) {
	finding := types.ImageScanFinding{
		Name:     nil,
		Severity: types.FindingSeverityMedium,
	}
	// Should not be ignored by CVE name when Name is nil
	ignored, _ := IsFindingIgnored(finding, []string{}, []string{"CVE-2024-0001"})
	if ignored {
		t.Error("expected finding with nil Name to not be ignored by CVE")
	}
	// Should be ignored by severity
	ignored, _ = IsFindingIgnored(finding, []string{"MEDIUM"}, []string{})
	if !ignored {
		t.Error("expected finding to be ignored by severity even with nil Name")
	}
}

func TestGetIgnoredFindings(t *testing.T) {
	findings := []types.ImageScanFinding{
		{Name: aws.String("CVE-2024-0001"), Severity: types.FindingSeverityHigh},
		{Name: aws.String("CVE-2024-0002"), Severity: types.FindingSeverityLow},
		{Name: aws.String("CVE-2024-0003"), Severity: types.FindingSeverityMedium},
	}

	ignored := GetIgnoredFindings(findings, []string{"LOW"}, []string{"CVE-2024-0001"})
	if len(ignored) != 2 {
		t.Fatalf("expected 2 ignored findings, got %d", len(ignored))
	}
}

func TestGetIgnoredFindings_NoneIgnored(t *testing.T) {
	findings := []types.ImageScanFinding{
		{Name: aws.String("CVE-2024-0001"), Severity: types.FindingSeverityHigh},
	}

	ignored := GetIgnoredFindings(findings, []string{}, []string{})
	if len(ignored) != 0 {
		t.Fatalf("expected 0 ignored findings, got %d", len(ignored))
	}
}

func TestGetIgnoredFindings_AllIgnored(t *testing.T) {
	findings := []types.ImageScanFinding{
		{Name: aws.String("CVE-2024-0001"), Severity: types.FindingSeverityHigh},
		{Name: aws.String("CVE-2024-0002"), Severity: types.FindingSeverityHigh},
	}

	ignored := GetIgnoredFindings(findings, []string{"HIGH"}, []string{})
	if len(ignored) != 2 {
		t.Fatalf("expected 2 ignored findings, got %d", len(ignored))
	}
}

func TestSortFindingsBySerityLevel(t *testing.T) {
	findings := []types.ImageScanFinding{
		{Name: aws.String("CVE-2024-0001"), Severity: types.FindingSeverityHigh},
		{Name: aws.String("CVE-2024-0002"), Severity: types.FindingSeverityLow},
		{Name: aws.String("CVE-2024-0003"), Severity: types.FindingSeverityHigh},
		{Name: aws.String("CVE-2024-0004"), Severity: types.FindingSeverityCritical},
	}

	sorted := SortFindingsBySerityLevel(findings)

	if len(sorted["CRITICAL"]) != 1 {
		t.Errorf("expected 1 CRITICAL finding, got %d", len(sorted["CRITICAL"]))
	}
	if len(sorted["HIGH"]) != 2 {
		t.Errorf("expected 2 HIGH findings, got %d", len(sorted["HIGH"]))
	}
	if len(sorted["LOW"]) != 1 {
		t.Errorf("expected 1 LOW finding, got %d", len(sorted["LOW"]))
	}
	if len(sorted["MEDIUM"]) != 0 {
		t.Errorf("expected 0 MEDIUM findings, got %d", len(sorted["MEDIUM"]))
	}
	if len(sorted["INFORMATIONAL"]) != 0 {
		t.Errorf("expected 0 INFORMATIONAL findings, got %d", len(sorted["INFORMATIONAL"]))
	}
	if len(sorted["UNDEFINED"]) != 0 {
		t.Errorf("expected 0 UNDEFINED findings, got %d", len(sorted["UNDEFINED"]))
	}
}

func TestSortFindingsBySerityLevel_EmptyFindings(t *testing.T) {
	sorted := SortFindingsBySerityLevel([]types.ImageScanFinding{})
	for _, severity := range GetFindingSeverityLevelsAsList() {
		if len(sorted[severity]) != 0 {
			t.Errorf("expected 0 findings for %s, got %d", severity, len(sorted[severity]))
		}
	}
}

func TestGetECRRepo_Valid(t *testing.T) {
	repo, err := GetECRRepo("123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}

func TestGetECRRepo_ValidWithSlash(t *testing.T) {
	repo, err := GetECRRepo("123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo/subpath")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}

func TestGetECRRepo_InvalidDomain(t *testing.T) {
	_, err := GetECRRepo("docker.io/library/nginx")
	if err == nil {
		t.Fatal("expected error for non-ECR registry, got nil")
	}
}

func TestGetECRRepo_InvalidFormat(t *testing.T) {
	_, err := GetECRRepo("not-a-valid-reference:::")
	if err == nil {
		t.Fatal("expected error for invalid reference, got nil")
	}
}

func TestSelectPlatformDigest_PrefersLinuxAmd64(t *testing.T) {
	manifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": [
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:arm64digest",
				"size": 1234,
				"platform": {"architecture": "arm64", "os": "linux"}
			},
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:amd64digest",
				"size": 5678,
				"platform": {"architecture": "amd64", "os": "linux"}
			}
		]
	}`
	digest, os, arch, err := selectPlatformDigest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != "sha256:amd64digest" {
		t.Errorf("expected sha256:amd64digest, got %s", digest)
	}
	if os != "linux" || arch != "amd64" {
		t.Errorf("expected linux/amd64, got %s/%s", os, arch)
	}
}

func TestSelectPlatformDigest_FallsBackToLinux(t *testing.T) {
	manifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
		"manifests": [
			{
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"digest": "sha256:windowsdigest",
				"size": 1234,
				"platform": {"architecture": "amd64", "os": "windows"}
			},
			{
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"digest": "sha256:linuxarm64",
				"size": 5678,
				"platform": {"architecture": "arm64", "os": "linux"}
			}
		]
	}`
	digest, os, arch, err := selectPlatformDigest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != "sha256:linuxarm64" {
		t.Errorf("expected sha256:linuxarm64, got %s", digest)
	}
	if os != "linux" || arch != "arm64" {
		t.Errorf("expected linux/arm64, got %s/%s", os, arch)
	}
}

func TestSelectPlatformDigest_SkipsAttestationManifests(t *testing.T) {
	// Buildx often includes attestation manifests with "unknown" OS
	manifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": [
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:attestation1",
				"size": 500,
				"platform": {"architecture": "unknown", "os": "unknown"}
			},
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:realimage",
				"size": 5678,
				"platform": {"architecture": "amd64", "os": "linux"}
			},
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:attestation2",
				"size": 500,
				"platform": {"architecture": "unknown", "os": "unknown"}
			}
		]
	}`
	digest, _, _, err := selectPlatformDigest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != "sha256:realimage" {
		t.Errorf("expected sha256:realimage, got %s", digest)
	}
}

func TestSelectPlatformDigest_EmptyManifestList(t *testing.T) {
	manifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []
	}`
	_, _, _, err := selectPlatformDigest(manifest)
	if err == nil {
		t.Fatal("expected error for empty manifest list, got nil")
	}
}

func TestSelectPlatformDigest_InvalidJSON(t *testing.T) {
	_, _, _, err := selectPlatformDigest("not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestSelectPlatformDigest_SingleManifest(t *testing.T) {
	manifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": [
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:onlyone",
				"size": 5678,
				"platform": {"architecture": "arm64", "os": "linux"}
			}
		]
	}`
	digest, os, arch, err := selectPlatformDigest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != "sha256:onlyone" {
		t.Errorf("expected sha256:onlyone, got %s", digest)
	}
	if os != "linux" || arch != "arm64" {
		t.Errorf("expected linux/arm64, got %s/%s", os, arch)
	}
}

func TestNewUnsupportedImageFinding(t *testing.T) {
	findings := newUnsupportedImageFinding("test description")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if *findings[0].Name != "ECR_ERROR_UNSUPPORTED_IMAGE" {
		t.Errorf("expected name ECR_ERROR_UNSUPPORTED_IMAGE, got %s", *findings[0].Name)
	}
	if *findings[0].Description != "test description" {
		t.Errorf("expected description 'test description', got %s", *findings[0].Description)
	}
	if findings[0].Severity != types.FindingSeverityInformational {
		t.Errorf("expected severity INFORMATIONAL, got %s", findings[0].Severity)
	}
}
