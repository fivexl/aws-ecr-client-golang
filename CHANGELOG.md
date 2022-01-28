### v0.4.0

* Fix for Bug:"/" inside repository name is automatically truncated

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
