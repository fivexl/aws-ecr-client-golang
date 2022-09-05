[![FivexL](https://releases.fivexl.io/fivexlbannergit.jpg)](https://fivexl.io/)

# aws-ecr-client

AWS ECR client for automated push to ECR and handling of vulnerability scanning results

Features:
* Automatically gets authorization token for ECR repo
* Can push image to "scanning silo" ECR repo before pushing image to the actual repo (recommended)
* Can push image only to "scanning silo" ECR repo and skip pushing image to the actual repo (useful for CI)
* Can ignore all CVE's of certain severity level (not recommended but useful when you have to deal with docker image over which you have no control)
* Can ignore individual CVE's (not recommended but useful when you might really really need to unblock that pipeline)
* Can output CVE scan report in Junit format so you can feed to to Jenkins or some other system for visibility

See examples below for more details

## Usage

```
NAME:
   aws-ecr-client-golang - AWS ECR client to automated push to ECR and handling of vulnerability.
                           Version v0.6.0

USAGE:
   aws-ecr-client-golang [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h                           show help (default: false)
   --ignore-cve value, -c value         Space-separated list of individual CVE's to ignore. (default: empty string) [$AWS_ECR_CLIENT_IGNORE_CVE]
   --ignore-levels value, -l value      Space-separated list of CVE severity levels to ignore. Valid severity levels are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNDEFINED (default: empty string) [$AWS_ECR_CLIENT_IGNORE_CVE_LEVEL]
   --images value, -i value             Space-separated list of full image references to push. [$AWS_ECR_CLIENT_IMAGES]
   --junit-report-path value, -j value  If set then CVE scan result will be written in JUNIT format to the path provided as a value. Useful for CI (like Jenkins) to keep ignored CVE visible [$AWS_ECR_CLIENT_JUNIT_REPORT_PATH]
   --scan-wait-timeout value            The max duration (in minutes) to wait for the image scan to complete. If exceeded, the operation will fail and the tag will not be pushed. (default: 20) [$AWS_ECR_CLIENT_SCAN_WAIT_TIMEOUT]
   --skip-push, -p                      Only push to scanning silo and do not push to destination repo even if there are no CVE's (useful for CI). (default: false) [$AWS_ECR_CLIENT_SKIP_PUSH]
   --stage-ecr-repo value, -s value     AWS ECR Repository where the image will be sent for scanning before pushing it to destination repo with the tag ecs-client-scan-<timestamp>. If omitted, then the repo of the first wiven image will be used. (default: empty string) [$AWS_ECR_CLIENT_STAGE_ECR_REPO]

  Find source code, usage examples, report issues, get support: https://github.com/fivexl/aws-ecr-client-golang
```

## Releases

Download official builds from [here](https://releases.fivexl.io/aws-ecr-client-golang/index.html)

## Examples

### Push of the real tag is stopped because of CVE

```
$ aws-ecr-client-golang --images XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:3.12.12
aws-ecr-client, version v0.6.0
Note: Stage repo is not specified - will use the the repo of the first given image as a scanning silo
Push image to the scanning repo as XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662393883
Checking scan result for the image XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662393883

Image scan status: COMPLETE

Found the following CVEs
+----------------+-----------+----------+-------------+---------------------------------------------------------------+
|      CVE       | SEVERITY  | IGNORED? | DESCRIPTION |                              URI                              |
+----------------+-----------+----------+-------------+---------------------------------------------------------------+
| CVE-2022-37434 | UNDEFINED | No       |             | https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37434 |
+----------------+-----------+----------+-------------+---------------------------------------------------------------+

Ignored CVE severity levels:
Ignored CVE's:

Final scan result: Failed
Error: there are CVEs found! Please, fix them first. Will not proceed with pushing to the destination registries
```

### Push of the real tag with ignored CVE

```
$ AWS_ECR_CLIENT_IGNORE_CVE=CVE-2022-37434 aws-ecr-client-golang --images XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:3.12.12
aws-ecr-client, version v0.6.0
Note: Stage repo is not specified - will use the the repo of the first given image as a scanning silo
Push image to the scanning repo as XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662393948
Checking scan result for the image XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662393948

Image scan status: COMPLETE

Found the following CVEs
+----------------+-----------+------------------------------+-------------+---------------------------------------------------------------+
|      CVE       | SEVERITY  |           IGNORED?           | DESCRIPTION |                              URI                              |
+----------------+-----------+------------------------------+-------------+---------------------------------------------------------------+
| CVE-2022-37434 | UNDEFINED | Yes (Ignored individual CVE) |             | https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37434 |
+----------------+-----------+------------------------------+-------------+---------------------------------------------------------------+

Ignored CVE severity levels:
Ignored CVE's:               CVE-2022-37434

Final scan result: Passed
Pushing: XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:3.12.12
Done
```

### Junit report example

```
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
	<testsuite tests="6" failures="1" time="6.000" name="Container Image CVE scan">
		<properties>
			<property name="go.version" value="go1.14.4"></property>
			<property name="coverage.statements.pct" value="100"></property>
		</properties>
		<testcase classname="Container Image CVE scan" name="CRITICAL" time="1.000"></testcase>
		<testcase classname="Container Image CVE scan" name="HIGH" time="1.000"></testcase>
		<testcase classname="Container Image CVE scan" name="MEDIUM" time="1.000"></testcase>
		<testcase classname="Container Image CVE scan" name="LOW" time="1.000">
			<failure message="Failed" type="">CVE-2020-28928</failure>
		</testcase>
		<testcase classname="Container Image CVE scan" name="INFORMATIONAL" time="1.000"></testcase>
		<testcase classname="Container Image CVE scan" name="UNDEFINED" time="1.000"></testcase>
	</testsuite>
</testsuites>
```

### Scratch images

The client handles unsupported images error (for example scratch) as another finding and thus user has a chance to ignore it by
ignoring `ECR_ERROR_UNSUPPORTED_IMAGE`

```
aws-ecr-client, version v0.6.0
Note: Stage repo is not specified - will use the the repo of the first given image as a scanning silo
Push image to the scanning repo as XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662392380
Checking scan result for the image XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/alpine:ecs-client-scan-1662392380

Found the following CVEs
+-----------------------------+---------------+------------------------------+--------------------------------+-----+
|             CVE             |   SEVERITY    |           IGNORED?           |          DESCRIPTION           | URI |
+-----------------------------+---------------+------------------------------+--------------------------------+-----+
| ECR_ERROR_UNSUPPORTED_IMAGE | INFORMATIONAL | Yes (Ignored individual CVE) | UnsupportedImageError: The     |     |
|                             |               |                              | operating system and/or        |     |
|                             |               |                              | package manager are not        |     |
|                             |               |                              | supported.                     |     |
+-----------------------------+---------------+------------------------------+--------------------------------+-----+

Ignored CVE severity levels:
Ignored CVE's:               ECR_ERROR_UNSUPPORTED_IMAGE

Final scan result: Passed
```
