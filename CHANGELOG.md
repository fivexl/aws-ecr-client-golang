### v0.6.0

**IMPORTANT: This release includes breaking changes!** Please check the migration guide: [MIGRATION-v0.6.md](./MIGRATION-v0.6.md)

* Handle full image references with new "--images" argument, https://github.com/fivexl/aws-ecr-client-golang/pull/19

### v0.5.3

* Fix handling the UnsupportedImageError, https://github.com/fivexl/aws-ecr-client-golang/pull/16
* Update dependencies, https://github.com/fivexl/aws-ecr-client-golang/pull/17

### v0.5.2

* bug fix: Use WaitForOutput to wait and retry ECR requests by @legal90 in https://github.com/fivexl/aws-ecr-client-golang/pull/15

### v0.5.1

* bug fix: repeated CVE levels in ignore configuration caused mistake in calculation of the number of ignored issues resulting in scan marked as passed when it actually failed
* drop forgotten debug print out

### v0.5.0

* Gracefuly handle unsupported image error and let use ignore it

### v0.4.0

* Added proper handling of / in the name of ECR repository
* Updated dependencies to address CVEs (containerd - GHSA-mvff-h3cj-wj9c, GHSA-5j5w-g665-5m35, GHSA-c2h3-6mxw-7mvq; opencontainers/image-spec - GHSA-77vh-xpmg-72qh)

### v0.3.0

* Added possibility to write CVE scanning report in Junit format
* Do not print docker push output to reduce noise

### v0.2.3

* Remove timeout from Docker operations
* More compact docker push output to reduce noise

### v0.2.2

* Fix the issue that prevented correct tagging of image destined to the scanning repo (in case of the separate scanning repo)

### v0.2.1

* Static binaries for use on Alpine Linux

### v0.2.0

* Added possibility to skip push to the destination repository even if there are no CVEs found (useful for CI)
* Added possibility to provide more tags to tag and push
* Output fixes and improvements

### v0.1.0

First version
