## Migration to v0.6.0 from older versions

The release v0.6.0 includes breaking changes caused by renaming and removing some CLI arguments. Please check the guideline below to see how to migrate your scripts.

#### Case: Push a single tag
Replace `--destination-repo`, `--tag` and `--additional-tags` with `--images`

BEFORE:
```
aws-ecr-client --destination-repo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine \
               --tag test
```
AFTER:
```
aws-ecr-client --images XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:test
```

#### Case: Push multiple tags
Replace `--destination-repo`, `--tag` and `--additional-tags` with `--images` (space separated)

BEFORE:
```
aws-ecr-client --destination-repo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine \
               --tag test \
               --additional-tags "foo bar"
```
AFTER:
```
aws-ecr-client --images "XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:test XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:foo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:bar"
```

#### Case: Use a desired stage repo
Replace `--stage-repo` with `stage-ecr-repo`

BEFORE:
```
aws-ecr-client --destination-repo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine \
               --tag test \
               --stage-repo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine-stage
```
AFTER:
```
aws-ecr-client --images XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine:test \
               --stage-ecr-repo XXXXXX.dkr.ecr.eu-central-1.amazonaws.com/alpine-stage
```
