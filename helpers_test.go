/*
Copyright 2022 Andrey Devyatkin.

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
)

func TestDedupList_NoDuplicates(t *testing.T) {
	input := []string{"a", "b", "c"}
	result := dedupList(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	expected := []string{"a", "b", "c"}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("expected result[%d] = %s, got %s", i, expected[i], v)
		}
	}
}

func TestDedupList_WithDuplicates(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "a"}
	result := dedupList(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	expected := []string{"a", "b", "c"}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("expected result[%d] = %s, got %s", i, expected[i], v)
		}
	}
}

func TestDedupList_EmptyList(t *testing.T) {
	result := dedupList([]string{})
	if len(result) != 0 {
		t.Fatalf("expected 0 items, got %d", len(result))
	}
}

func TestDedupList_SingleItem(t *testing.T) {
	result := dedupList([]string{"x"})
	if len(result) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result))
	}
	if result[0] != "x" {
		t.Errorf("expected x, got %s", result[0])
	}
}

func TestDedupList_AllDuplicates(t *testing.T) {
	input := []string{"a", "a", "a"}
	result := dedupList(input)
	if len(result) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result))
	}
	if result[0] != "a" {
		t.Errorf("expected a, got %s", result[0])
	}
}

func TestDedupList_PreservesOrder(t *testing.T) {
	input := []string{"c", "a", "b", "a", "c"}
	result := dedupList(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	// Should preserve first-seen order
	expected := []string{"c", "a", "b"}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("expected result[%d] = %s, got %s", i, expected[i], v)
		}
	}
}
