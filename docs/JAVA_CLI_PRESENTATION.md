# API Security Scanner Java CLI

## Executive Summary

`apisec-java` is a Java 17 command-line API security scanner for authorized defensive testing. It accepts a user-provided `curl` command, executes the original request as a baseline, applies safe OWASP API Security rule mutations, evaluates responses, prints a readable terminal report, exports JSON, and can send the report to a webhook.

The Java CLI uses the same `SecurityRuleGroup` JSON contract as the APIWiz runtime/Mongo collection. This keeps scanner rules portable between the CLI and runtime security processing.

## Why This Exists

The goal is to give engineering and security teams a local, repeatable API security validation tool that works from the exact request developers already use: a `curl` command.

It helps identify defensive API issues such as:

- Missing or weak authentication checks
- Broken object-level authorization signals
- Sensitive fields exposed in responses
- Missing rate-limit signals
- Security misconfiguration
- Unsafe webhook/API consumption patterns

The tool is explicitly defensive and scoped to one user-provided endpoint at a time.

## What The CLI Does

Scan flow:

1. Parse the supplied curl command.
2. Normalize method, URL, headers, query params, cookies, and body.
3. Execute the original request as the baseline.
4. Load local `SecurityRuleGroup` JSON.
5. Evaluate rule group preconditions.
6. Generate safe request mutations.
7. Execute mutated requests with timeout and request limits.
8. Evaluate runtime-style assertions.
9. Generate findings.
10. Print a concise terminal report.
11. Export a redacted JSON report.
12. Optionally deliver the JSON report to a webhook.

## Key Capabilities

### Curl-Based Scanning

Example:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar scan \
  --rules rules/owasp-api-2023.json \
  --curl "curl --location 'http://localhost:9002/itorix/v1/permissions' --header 'Content-Type: application/json' --header 'x-apikey: test'"
```

### OWASP API Security Rules

The bundled rule group maps to OWASP API Security Top 10 2023 and currently contains 61 rules.

Rule validation:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar rules validate \
  --file rules/owasp-api-2023.json
```

Expected output:

```json
{
  "name": "OWASP API Security Top 10 2023",
  "rules": 61,
  "valid": true,
  "version": "1.1.0"
}
```

### Runtime-Compatible Rule Schema

The Java CLI supports the same rule group structure used by the Mongo collection:

- `SecurityRuleGroup`
- `SecurityAssertion`
- `precondition.expression`
- `precondition.placeholders`
- `rule.assertion.expression`
- `rule.assertion.placeholders`
- metadata entries such as `owasp`, `cwe`, `cves`, `scanType`, `curlMutations`, and `remediation`

Assertions use runtime-style keys:

```txt
request.method
request.path
request.headers.<name>
request.queryParams.<name>
request.body
response.code
response.headers.<name>
response.body
baseline.code
baseline.bodySimilarity
```

This avoids CLI-only assertion keys and keeps rules compatible with APIWiz runtime processing.

## Important False-Positive Controls

### Credential-Aware Auth Mutation

The scanner detects the actual credential used by the request:

- `Authorization`
- `X-API-Key`
- `x-apikey`
- `Api-Key`
- `X-Auth-Token`
- session cookies
- query tokens such as `api_key`, `apikey`, `access_token`, `token`

If the API uses `x-apikey`, the scanner removes `x-apikey`. It does not incorrectly remove `Authorization` when that header is absent.

Correct finding evidence:

```txt
Endpoint returned 200 after x-apikey header was removed.
```

### BOLA Rule Preconditions

BOLA rules run only when an object identifier exists.

Examples that run BOLA checks:

```txt
/users/123
/orders/789
/accounts/550e8400-e29b-41d4-a716-446655440000
?userId=123
?accountId=abc
X-Tenant-ID: tenant-1
```

Examples that skip object-ID BOLA checks:

```txt
/v1/permissions
/health
/metadata
```

Skipped reason:

```txt
No object identifier detected.
```

## Console Report UX

The default terminal report is intentionally focused on action:

1. Scan header
2. Summary
3. Failed severity summary
4. Critical/high failed findings
5. Medium/low failed findings
6. Skipped count
7. Critical details and remediation
8. JSON export path
9. Webhook status

Passed rules are hidden by default to reduce noise.

Expanded output:

```sh
--show-passed
--show-skipped
--verbose
```

Full data is always available in the JSON report.

## Safety Controls

The scanner is designed for authorized defensive testing only.

Safety behavior:

- Scans only the endpoint provided by the user.
- Does not crawl or discover additional endpoints.
- Limits requests per rule.
- Dangerous method tampering is disabled by default.
- `DELETE`, `PUT`, and `PATCH` mutations require explicit opt-in unless the original request already used that method.
- CVE-specific rules do not claim detection without product/version evidence.
- SSRF-style tests are passive unless controlled callback context exists.
- Credential brute force and aggressive fuzzing are not implemented.

Dangerous opt-in:

```sh
--allow-dangerous
```

## Redaction

Secrets are redacted from console output, JSON reports, and webhook payloads.

Redacted keys include:

```txt
Authorization
Cookie
Set-Cookie
X-API-Key
x-apikey
api_key
apikey
access_token
refresh_token
token
password
passwd
secret
client_secret
private_key
```

Redacted value:

```txt
[REDACTED]
```

## Commands

### Configure Once

The Java CLI loads this properties file by default:

```txt
~/.apisec/apisec-java.properties
```

Sample file:

```txt
apisec-java/apisec-java.example.properties
```

Important properties:

```properties
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

rules.directory=../apisec/rules
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

After this, scans do not need repeated rules/report/webhook flags.

### Scan

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../apisec/rules/owasp-api-2023.json \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

### Validate Rules

```sh
java -jar target/apisec-java-1.0.0.jar rules validate \
  --file ../apisec/rules/owasp-api-2023.json
```

### List Rules

```sh
java -jar target/apisec-java-1.0.0.jar rules list \
  --rules-dir ../apisec/rules
```

### Show Config

```sh
java -jar target/apisec-java-1.0.0.jar config show
```

### Initialize Config

```sh
java -jar target/apisec-java-1.0.0.jar config init
```

### Pull Remote Rules

```sh
java -jar target/apisec-java-1.0.0.jar pull
```

The pull URL and tenant can be configured once:

```properties
rules.pull.sourceUrl=http://localhost:8073/v1/apiwiz-api-security/cli/pull/rule-group
rules.pull.tenant=acme-team-dev
rules.pull.tokenEnv=APISEC_RULES_TOKEN
```

The CLI sends:

```txt
tenant: acme-team-dev
```

### Send Reports To API Security

The API security service exposes a CLI report webhook:

```txt
POST /v1/apiwiz-api-security/cli/webhook
```

Java CLI example:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../apisec/rules/owasp-api-2023.json \
  --curl-file request.curl \
  --webhook http://localhost:9002/v1/apiwiz-api-security/cli/webhook \
  --webhook-tenant my-tenant \
  --webhook-secret "$APISEC_CLI_WEBHOOK_SECRET"
```

Webhook headers sent by the CLI:

```txt
tenant: <tenant>
X-ApiSec-Scan-Id: <scanId>
X-ApiSec-Signature: sha256=<hmac>
```

The API security service verifies the signature when `itorix.api.security.cli.webhook.secret` is configured and stores the redacted report in Mongo collection `apiSecCliScanReports`.

## Java And Go Parity

The repository contains both Go and Java implementations.

Business logic parity is protected by a parity test:

```sh
go test -run TestGoJavaReportParity -count=1
```

The parity test:

- Starts a local API server.
- Runs the Go CLI with the same curl and rules.
- Runs the Java CLI with the same curl and rules.
- Parses both JSON reports.
- Compares summary counts.
- Compares every rule ID status.

Covered parity scenarios:

- `x-apikey` request to `/v1/permissions`
- bearer `Authorization` request to `/users/123?id=123`

Current parity status:

```txt
Go and Java are business-logic aligned for the tested scanner flows.
```

## Build

```sh
cd apisec-java
mvn test
mvn package -DskipTests
```

Runnable jar:

```txt
apisec-java/target/apisec-java-1.0.0.jar
```

Run help:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar --help
```

## IntelliJ Debug Setup

Open:

```txt
/Users/madhusudantripathy/Documents/apisec/apisec-java
```

Create an Application run configuration:

```txt
Main class: com.apisec.cli.ApiSec
Working directory: /Users/madhusudantripathy/Documents/apisec/apisec-java
Program arguments:
scan --rules ../apisec/rules/owasp-api-2023.json --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

Useful breakpoints:

```txt
com.apisec.cli.ScanCommand.call
com.apisec.engine.ScannerEngine.run
com.apisec.engine.ScannerEngine.evaluateRule
com.apisec.eval.Evaluator.assertion
com.apisec.mutate.Mutator.generate
```

## Demo Script

1. Validate rules:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar rules validate \
  --file rules/owasp-api-2023.json
```

2. Run scan:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar scan \
  --rules rules/owasp-api-2023.json \
  --curl "curl --location 'http://localhost:9002/itorix/v1/permissions' --header 'Content-Type: application/json' --header 'x-apikey: test'"
```

3. Show JSON export path in console.

4. Explain that default console output focuses on failed findings, while full rule detail is in JSON.

5. Run verbose mode if needed:

```sh
java -jar apisec-java/target/apisec-java-1.0.0.jar scan \
  --rules rules/owasp-api-2023.json \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'" \
  --verbose
```

## Current Limitations

- The CLI evaluates one user-provided endpoint per scan.
- It does not crawl APIs.
- It does not brute force credentials.
- It does not perform destructive exploitation by default.
- Java and Go parity is currently tested for representative auth and BOLA flows; more parity scenarios can be added for broader coverage.
- Direct dependency on the full `apiwiz-common` module was avoided to keep the CLI lightweight; the shared contract is the `SecurityRuleGroup` JSON schema and placeholder semantics.

## Recommended Next Steps

1. Add more parity scenarios for JSON-body mutation rules.
2. Add a native binary distribution using GraalVM if a no-Java-runtime executable is required.
3. Publish the OWASP rule group through the same remote rules API used by runtime services.
4. Add CI to run both Java tests and Go/Java parity tests.
5. Add an internal release package with jar, wrapper script, default rules, and documentation.
