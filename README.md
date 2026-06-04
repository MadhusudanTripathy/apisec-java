# apisec-java

Java 17 implementation of the defensive `apisec` CLI.

It mirrors the Go CLI flow:

- parse a user-provided curl command
- execute the original request as baseline
- load the shared `SecurityRuleGroup` JSON schema
- run safe OWASP API Security mutations
- evaluate runtime-style placeholders and expressions
- print a concise terminal report
- export JSON
- optionally deliver the report to a webhook

The Java implementation intentionally keeps the same rule JSON contract used by Mongo/APIWiz runtime. It does not require the full Spring runtime dependency graph; the shared boundary is the `SecurityRuleGroup` JSON document and placeholder semantics.

## Build

```sh
cd apisec-java
mvn test
mvn package
```

## Run

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../rules/owasp-api-2023.json \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

## Configure Once

The Java CLI loads this properties file by default:

```txt
~/.apisec/apisec-java.properties
```

Create it from the sample:

```sh
mkdir -p ~/.apisec
cp apisec-java.example.properties ~/.apisec/apisec-java.properties
```

Example:

```properties
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

rules.directory=../rules
rules.activeGroups=owasp-api-2023

reports.directory=~/.apisec/java-reports
reports.fileNamePattern=scan_{timestamp}_{scanId}.json
reports.redactSecrets=true

webhook.enabled=true
webhook.url=http://localhost:9002/v1/apiwiz-api-security/cli/webhook
webhook.secret=${APISEC_CLI_WEBHOOK_SECRET}
webhook.tenant=my-tenant
webhook.timeoutSeconds=5
webhook.retries=3
```

After that, a scan only needs the curl:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

Use a custom config file:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --config ./apisec-java.properties \
  --curl-file request.curl
```

When the rules directory is configured, `--rules` may also be a group id:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules-dir ../rules \
  --rules owasp-api-2023 \
  --curl-file request.curl
```

Use concise default output, or expand it:

```sh
java -jar target/apisec-java-1.0.0.jar scan --show-passed --show-skipped --curl-file request.curl
java -jar target/apisec-java-1.0.0.jar scan --verbose --curl-file request.curl
```

## Validate Rules

```sh
java -jar target/apisec-java-1.0.0.jar rules validate --file ../rules/owasp-api-2023.json
```

## Pull Rules

```sh
java -jar target/apisec-java-1.0.0.jar pull \
  --source https://rules.example.com/api/security/rule-groups \
  --token "$APISEC_RULES_TOKEN"
```

Existing rule files are not overwritten unless `--overwrite` is provided.

## Send Reports To API Security

The API security service exposes a CLI report webhook at:

```txt
POST /v1/apiwiz-api-security/cli/webhook
```

Send scan reports to it:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../rules/owasp-api-2023.json \
  --curl-file request.curl \
  --webhook http://localhost:9002/v1/apiwiz-api-security/cli/webhook \
  --webhook-tenant my-tenant \
  --webhook-secret "$APISEC_CLI_WEBHOOK_SECRET"
```

The CLI sends:

- `tenant`
- `X-ApiSec-Scan-Id`
- `X-ApiSec-Signature: sha256=<hmac>` when `--webhook-secret` is provided
