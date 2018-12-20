# README

```bash
AWS_KINESIS_DATA_STREAM=gcld-bosh-firehose \
AWS_REGION=ap-southeast-2 \
INSTANCE=foobar \
FILES_TO_WATCH=/var/log/messages:/var/log/secure \
DIRS_TO_WATCH=/var/log/**/*.log:/var/vcap/sys/log/**/*.log \
    ./cga-logs-to-kinesis
```
