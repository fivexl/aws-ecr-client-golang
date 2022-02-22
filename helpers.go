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

func dedupList(inList []string) []string {
	// Use look up table to avoid iterating over the list
	// again and again
	lookUpTable := make(map[string]bool)
	outList := []string{}
	for _, item := range inList {
		// if the item is in the look up table then we should
		// have it in the list
		if _, value := lookUpTable[item]; !value {
			lookUpTable[item] = true
			outList = append(outList, item)
		}
	}
	return outList
}
