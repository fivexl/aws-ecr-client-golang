[![FivexL](https://releases.fivexl.io/fivexlbannergit.jpg)](https://fivexl.io/)

# aws-ecr-client

AWS ECR client for automated push to ECR and handling of vulnerability scanning results

Features:
* Automatically gets authorization token for ECR repo
* Can push image to "scanning silo" ECR repo before pushing image to the actual repo (recommended)
* Can ignore all CVE's of certain level (not recommended but useful when you have to deal with docker image over which you have no control)
* Can ignore individual CVE's (not recommended but useful when you might really really need to unblock that pipeline)

## Usage



## Example

### Push of the real tag is stopped because of CVE

```
$ aws-ecr-client -d XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine -t test

Note: Stage repo is not specified - will use destination repo as scanning silo

First push image to scanning repo XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine with the tag alpine-test-scan-1627040431

docker-push: The push refers to repository [XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine]
docker-push: Preparing
docker-push: Layer already exists
docker-push: alpine-test-scan-1627040431: digest: sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d size: 528

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

docker-push: The push refers to repository [XXXXXXXXXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine]
docker-push: Preparing
docker-push: Layer already exists
docker-push: alpine-test-scan-1627040374: digest: sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d size: 528

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

docker-push: The push refers to repository [798424800762.dkr.ecr.eu-central-1.amazonaws.com/alpine]
docker-push: Preparing
docker-push: Layer already exists
docker-push: test: digest: sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d size: 528

Pushing 798424800762.dkr.ecr.eu-central-1.amazonaws.com/alpine:latest

docker-push: The push refers to repository [798424800762.dkr.ecr.eu-central-1.amazonaws.com/alpine]
docker-push: Preparing
docker-push: Layer already exists
docker-push: latest: digest: sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d size: 528

```
