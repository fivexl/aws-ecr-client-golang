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
   aws-ecr-client-linux-amd64 - AWS ECR client to automated push to ECR and handling of vulnerability.
Version v0.4.0

USAGE:
   aws-ecr-client-linux-amd64 [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --destination-repo value, -d value   Final destination of the image [$AWS_ECR_CLIENT_DESTINATION_REPO]
   --tag value, -t value                Image tag to push. Tag should already exist. [$AWS_ECR_CLIENT_IMAGE_TAG]
   --additional-tags value, -a value    Space-separated list of tags to add to the image and push. (default: latest) [$AWS_ECR_CLIENT_ADDITIONAL_TAGS]
   --stage-repo value, -s value         Repository where image will be sent for scanning before pushing it to destination repo with the tag <destination-repo-name>-<tag>-scan-<timestamp>. Will push directly to destination repo with the specified tag if no value provided (default: empty string) [$AWS_ECR_CLIENT_STAGE_REPO]
   --ignore-levels value, -l value      Space-separated list of CVE severity levels to ignore. Valid severity levels are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNDEFINED (default: empty string) [$AWS_ECR_CLIENT_IGNORE_CVE_LEVEL]
   --ignore-cve value, -c value         Space-separated list of individual CVE's to ignore. (default: empty string) [$AWS_ECR_CLIENT_IGNORE_CVE]
   --junit-report-path value, -j value  If set then CVE scan result will be written in JUNIT format to the path provided as a value. Useful for CI (like Jenkins) to keep ignored CVE visible [$AWS_ECR_CLIENT_JUNIT_REPORT_PATH]
   --skip-push, -p                      Only push to scanning silo and do not push to destination repo even if there are no CVE's (useful for CI). (default: false) [$AWS_ECR_CLIENT_SKIP_PUSH]
   --help, -h                           show help (default: false)


  Find source code, usage examples, report issues, get support: https://github.com/fivexl/aws-ecr-client-golang
```

## Releases

Download official builds from [here](https://releases.fivexl.io/aws-ecr-client-golang/index.html)

## Examples

### Push of the real tag is stopped because of CVE

```
$ aws-ecr-client -d XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine -t test

Note: Stage repo is not specified - will use destination repo as scanning silo

First push image to scanning repo XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine with the tag alpine-test-scan-1627040431

Checking scan result for the image XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:alpine-test-scan-1627040431

Image scan status: COMPLETE

Found the following CVEs
+----------------+----------+----------+-------------+---------------------------------------------------------------+
|      CVE       | SEVERITY | IGNORED? | DESCRIPTION |                              URI                              |
+----------------+----------+----------+-------------+---------------------------------------------------------------+
| CVE-2020-28928 | LOW      | No       |             | https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28928 |
+----------------+----------+----------+-------------+---------------------------------------------------------------+

Ignored CVE severity levels:
Ignored CVE's:

Final scan result: Failed

There are CVEs found. Fix them first. Will not proceed with pushing XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:test
```

### Push of the real tag with ignored CVE

```
$ AWS_ECR_CLIENT_IGNORE_CVE=CVE-2020-28928 aws-ecr-client-linux-amd64 -d XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine -t test

Note: Stage repo is not specified - will use destination repo as scanning silo

First push image to scanning repo XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine with the tag alpine-test-scan-1627040374

Checking scan result for the image XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:alpine-test-scan-1627040374

Image scan status: COMPLETE

Found the following CVEs
+----------------+----------+------------------------------+-------------+---------------------------------------------------------------+
|      CVE       | SEVERITY |           IGNORED?           | DESCRIPTION |                              URI                              |
+----------------+----------+------------------------------+-------------+---------------------------------------------------------------+
| CVE-2020-28928 | LOW      | Yes (ignored individual CVE) |             | https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28928 |
+----------------+----------+------------------------------+-------------+---------------------------------------------------------------+

Ignored CVE severity levels:
Ignored CVE's:               CVE-2020-28928

Final scan result: Passed

Pushing 798424800762.dkr.ecr.eu-central-1.amazonaws.com/alpine:test

Pushing additional tags: latest

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
aws-ecr-client, version v0.5.0

Note: Stage repo is not specified - will use destination repo as scanning silo

First push image to scanning repo as XXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:alpine-test-scratch-scan-1644784364

Checking scan result for the image XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:alpine-test-scratch-scan-1644784364

Image scan status: FAILED

Found the following CVEs
+-----------------------------+---------------+------------------------------+--------------------------------+-----+
|             CVE             |   SEVERITY    |           IGNORED?           |          DESCRIPTION           | URI |
+-----------------------------+---------------+------------------------------+--------------------------------+-----+
| ECR_ERROR_UNSUPPORTED_IMAGE | INFORMATIONAL | Yes (ignored individual CVE) | UnsupportedImageError: The     |     |
|                             |               |                              | operating system and/or        |     |
|                             |               |                              | package manager are not        |     |
|                             |               |                              | supported.                     |     |
+-----------------------------+---------------+------------------------------+--------------------------------+-----+

Ignored CVE severity levels:
Ignored CVE's:               ECR_ERROR_UNSUPPORTED_IMAGE

Final scan result: Passed

Writing junit report to: /tmp/tmp.zYXzmPu3yM

Pushing XXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:test-scratch

Pushing additional tags: latest
```
