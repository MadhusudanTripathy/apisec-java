# Java CLI Explained Simply

This document explains the Java `apisec` CLI from end to end in simple language.

Think of the CLI as a careful security tester that takes one `curl` command, sends it once normally, then sends a few safe changed versions of the same request, and checks whether the API behaved safely.

## The Big Picture

The Java CLI does this:

```txt
curl command
  -> parse into request model
  -> send original request
  -> load security rules
  -> decide which rules apply
  -> create safe mutations
  -> send mutated requests
  -> evaluate responses
  -> create findings
  -> print console report
  -> write JSON report
  -> optionally send report to API Security webhook
```

In one sentence:

```txt
The CLI checks whether an API endpoint still behaves securely when common safe security test conditions are applied.
```

## Important Folder Structure

The Java CLI lives here:

```txt
apisec-java/
```

Important files:

```txt
apisec-java/pom.xml
apisec-java/src/main/java/com/apisec/cli
apisec-java/src/main/java/com/apisec/config
apisec-java/src/main/java/com/apisec/curl
apisec-java/src/main/java/com/apisec/engine
apisec-java/src/main/java/com/apisec/eval
apisec-java/src/main/java/com/apisec/mutate
apisec-java/src/main/java/com/apisec/report
apisec-java/src/main/java/com/apisec/rules
apisec-java/src/main/java/com/apisec/webhook
apisec-java/src/test/java/com/apisec
```

The shared rules live outside the Java project:

```txt
rules/owasp-api-2023.json
```

That same rule JSON is used by the Go CLI and Java CLI.

## Main Packages

### `com.apisec.cli`

This is the command-line layer.

It answers:

```txt
What command did the user run?
What flags did they pass?
Which scanner function should be called?
```

Important classes:

```txt
ApiSec.java
ScanCommand.java
RulesCommand.java
ConfigCommand.java
PullCommand.java
```

`ApiSec.java` is the entry point.

When you run:

```sh
java -jar target/apisec-java-1.0.0.jar scan ...
```

Java starts here:

```java
com.apisec.cli.ApiSec.main(...)
```

Then picocli routes the command to:

```java
ScanCommand.call()
```

### `com.apisec.config`

This reads configuration.

Important class:

```txt
AppConfig.java
```

It stores settings like:

```txt
rules directory
reports directory
webhook URL
webhook tenant
webhook secret
timeout
max requests per rule
safe/dangerous mode
redaction
```

Config priority is:

```txt
CLI flags override environment variables
environment variables override config file
config file overrides defaults
```

So if config says:

```properties
webhook.enabled=false
```

but you pass:

```sh
--webhook http://localhost:9002/v1/apiwiz-api-security/cli/webhook
```

then CLI wins.

### `com.apisec.curl`

This parses the user’s curl command.

Important class:

```txt
CurlParser.java
```

Example input:

```sh
curl --location 'http://localhost:9002/itorix/v1/permissions' \
  --header 'Content-Type: application/json' \
  --header 'x-apikey: test'
```

The parser turns it into a Java object:

```java
RequestModel
```

That model contains:

```txt
method  = GET
url     = http://localhost:9002/itorix/v1/permissions
scheme  = http
host    = localhost
path    = /itorix/v1/permissions
headers = Content-Type, x-apikey
query   = query params if present
cookies = cookies if present
body    = request body if present
```

### `com.apisec.model`

This contains simple data objects.

Important classes:

```txt
RequestModel.java
ResponseModel.java
```

`RequestModel` means:

```txt
What request should we send?
```

`ResponseModel` means:

```txt
What did the server return?
```

### `com.apisec.rules`

This loads and understands rule JSON.

Important classes:

```txt
RuleModels.java
RuleLoader.java
```

`RuleModels.java` matches the Mongo/APIWiz rule schema:

```txt
SecurityRuleGroup
SecurityAssertion
Placeholder
Metadata
Mutation metadata
```

The Java names are simpler, but the JSON shape is compatible.

The CLI reads:

```txt
rules/owasp-api-2023.json
```

and turns it into Java objects.

### `com.apisec.engine`

This is the brain of the scanner.

Important class:

```txt
ScannerEngine.java
```

Most business logic lives here.

It decides:

```txt
Run baseline request
Load rules
Check preconditions
Skip unsafe or irrelevant rules
Generate mutations
Execute mutated requests
Evaluate findings
Build report
Send webhook
```

If you need to debug scanner logic, start here.

### `com.apisec.mutate`

This changes requests safely.

Important class:

```txt
Mutator.java
```

Example:

Original request:

```txt
GET /itorix/v1/permissions
x-apikey: test
```

Mutation:

```txt
remove x-apikey header
```

Mutated request:

```txt
GET /itorix/v1/permissions
```

The mutator supports operations like:

```txt
REMOVE_HEADER
REPLACE_HEADER
ADD_HEADER
REMOVE_COOKIE
REMOVE_QUERY_PARAM
REPLACE_QUERY_PARAM
REPLACE_PATH_ID
ADD_JSON_FIELD
REMOVE_JSON_FIELD
CHANGE_METHOD
MALFORM_JSON
OPTIONS_METHOD
TRACE_METHOD
```

Dangerous methods like `DELETE`, `PUT`, and `PATCH` are blocked unless explicitly allowed.

### `com.apisec.eval`

This checks whether a rule passed or failed.

Important class:

```txt
Evaluator.java
```

Rules contain placeholders like:

```json
{
  "rule": "NOT_EQUAL_TO",
  "key": "response.code",
  "value": "401"
}
```

That means:

```txt
Check if response status code is not 401.
```

The evaluator supports keys like:

```txt
request.method
request.path
request.headers.x-apikey
request.queryParams.id
response.code
response.body
response.headers.Server
baseline.code
baseline.bodySimilarity
```

### `com.apisec.report`

This creates the output.

Important classes:

```txt
ReportModels.java
Reporter.java
```

It creates:

```txt
console report
JSON report
summary counts
findings
webhook status
```

The console report is human-friendly.

The JSON report is complete and machine-readable.

### `com.apisec.webhook`

This sends reports to another API.

Important class:

```txt
WebhookClient.java
```

It sends:

```txt
POST webhook URL
Content-Type: application/json
tenant: <tenant>
X-ApiSec-Scan-Id: <scanId>
X-ApiSec-Signature: sha256=<hmac>
```

If webhook delivery fails, the scan still completes.

## Full Scan Flow In Detail

Let’s use this example:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../apisec/rules/owasp-api-2023.json \
  --curl "curl --location 'http://localhost:9002/itorix/v1/permissions' --header 'Content-Type: application/json' --header 'x-apikey: test'"
```

### Step 1: CLI Starts

Java starts at:

```java
ApiSec.main()
```

picocli sees:

```txt
scan
```

and calls:

```java
ScanCommand.call()
```

### Step 2: Config Is Loaded

`ScanCommand` calls:

```java
AppConfig.resolve(...)
```

The config includes:

```txt
rules directory
report directory
webhook details
timeouts
safety settings
```

### Step 3: Curl Is Parsed

`ScannerEngine.run()` calls:

```java
CurlParser.parse(curl)
```

This produces:

```java
RequestModel
```

For the example:

```txt
method: GET
path: /itorix/v1/permissions
header: Content-Type = application/json
header: x-apikey = test
```

### Step 4: Baseline Request Is Sent

The scanner sends the original request exactly once.

This is called the baseline.

Example:

```txt
GET /itorix/v1/permissions
x-apikey: test
```

The response might be:

```txt
200 OK
{"permissions":["read"]}
```

This is stored as:

```java
ResponseModel baseline
```

### Step 5: Rules Are Loaded

The scanner loads:

```txt
owasp-api-2023.json
```

That file contains 61 rules.

Each rule has:

```txt
ruleId
name
description
priority
assertion
metadata
curlMutations
remediation
```

Example rule:

```txt
API2-AUTH-001
Endpoint should reject missing authentication
```

### Step 6: Rule Group Precondition Is Checked

Before running rules, the scanner checks if the group applies.

For example:

```txt
Does the request exist?
Does it have URL/path/header/body/query info?
```

If the group does not apply, all its rules are skipped.

### Step 7: Each Rule Is Evaluated

For every rule, the scanner asks:

```txt
Should this rule run?
Is it safe?
Does the request have the needed input?
Does it require auth?
Does it require object ID?
Does it require alternate user curl?
```

If not, the rule becomes:

```txt
SKIPPED
```

## Important Business Logic

### Auth Detection

The scanner detects auth credentials.

Supported credentials:

```txt
Authorization
X-API-Key
x-apikey
Api-Key
X-Auth-Token
session cookies
api_key query param
apikey query param
access_token query param
token query param
```

For your request:

```txt
x-apikey: test
```

The scanner understands:

```txt
This endpoint uses API key authentication.
```

So it creates this mutation:

```txt
remove x-apikey header
```

It does not create this wrong mutation:

```txt
remove Authorization header
```

That avoids a false positive.

### Auth Rule Example

Original request:

```txt
GET /itorix/v1/permissions
x-apikey: test
```

Mutated request:

```txt
GET /itorix/v1/permissions
```

Expected secure behavior:

```txt
401 Unauthorized
or
403 Forbidden
```

Unsafe behavior:

```txt
200 OK
```

If the API returns `200` after removing `x-apikey`, the finding says:

```txt
Endpoint returned 200 after x-apikey header was removed.
```

### BOLA Detection

BOLA means:

```txt
Broken Object Level Authorization
```

Simple meaning:

```txt
Can user A access user B's object by changing an ID?
```

Example endpoint with object ID:

```txt
/users/123
```

The scanner can test:

```txt
/users/999999
```

But your endpoint:

```txt
/itorix/v1/permissions
```

does not contain an object ID.

So BOLA object-ID rules should not run.

They are skipped with:

```txt
No object identifier detected.
```

This avoids false positives.

### Passive Rules

Some rules do not send mutations.

They only inspect the baseline response.

Example:

```txt
Does the response expose sensitive fields?
Does the response show stack traces?
Does the response include server version headers?
```

These are passive because they only look.

### Active-Safe Rules

Some rules send changed requests.

Examples:

```txt
remove auth header
change object ID
send malformed JSON
send OPTIONS
change pagination limit
```

They are called active-safe because they send requests, but avoid destructive behavior.

### Dangerous Rules

Dangerous operations are disabled by default.

Examples:

```txt
DELETE
PUT
PATCH
```

They run only with:

```sh
--allow-dangerous
```

## Finding Statuses

Every rule becomes one of these:

```txt
PASSED
FAILED
SKIPPED
ERROR
```

Meaning:

```txt
PASSED  = API behaved safely for this rule
FAILED  = rule found a possible security issue
SKIPPED = rule did not apply or could not safely run
ERROR   = request or evaluation had an error
```

## Assertion Logic

A rule assertion is a condition.

Example:

```txt
After auth is removed, response.code should be 401 or 403.
```

The rule may express this as:

```txt
response.code NOT_EQUAL_TO 401
AND
response.code NOT_EQUAL_TO 403
```

This expression means:

```txt
If response is not 401 and not 403, then it is a threat.
```

So:

```txt
response 401 -> PASSED
response 403 -> PASSED
response 200 -> FAILED
```

## Report Output

### Console Report

The console report is short by default.

It shows:

```txt
scan id
target
rule group
summary
failed findings
critical details
export path
webhook status
```

Passed checks are hidden by default.

To show everything:

```sh
--verbose
```

### JSON Report

The JSON report contains everything.

It includes:

```txt
scanId
startedAt
finishedAt
durationMs
target
ruleGroups
summary
findings
webhook status
```

Reports are written to:

```txt
~/.apisec/reports
```

or whatever is configured.

## Webhook Flow

If webhook is enabled, the CLI sends the JSON report after the scan.

Example config:

```properties
webhook.enabled=true
webhook.url=http://localhost:9002/v1/apiwiz-api-security/cli/webhook
webhook.tenant=my-tenant
webhook.secret=${APISEC_CLI_WEBHOOK_SECRET}
```

The CLI sends:

```txt
POST /v1/apiwiz-api-security/cli/webhook
tenant: my-tenant
X-ApiSec-Scan-Id: scan_xxxxxxxx
X-ApiSec-Signature: sha256=<hmac>
Content-Type: application/json
```

The API security service receives it and stores it in Mongo:

```txt
apiSecCliScanReports
```

## Config

The Java CLI supports config so you do not repeat flags every time.

Default Java config path:

```txt
~/.apisec/apisec-java.properties
```

Sample:

```txt
apisec-java/apisec-java.example.properties
```

Example:

```properties
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

rules.directory=../apisec/rules
rules.activeGroups=owasp-api-2023
rules.pull.sourceUrl=http://localhost:8073/v1/apiwiz-api-security/cli/pull/rule-group
rules.pull.tenant=acme-team-dev
rules.pull.tokenEnv=APISEC_RULES_TOKEN

reports.directory=~/.apisec/java-reports

webhook.enabled=true
webhook.url=http://localhost:9002/v1/apiwiz-api-security/cli/webhook
webhook.tenant=my-tenant
webhook.secret=${APISEC_CLI_WEBHOOK_SECRET}
```

Then scan can be simple:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

Pull can also be simple after config:

```sh
java -jar target/apisec-java-1.0.0.jar pull
```

That calls the configured rule-group API and sends:

```txt
tenant: acme-team-dev
```

## Redaction

The scanner must not print secrets.

It redacts values for keys like:

```txt
Authorization
x-apikey
Cookie
api_key
token
password
secret
private_key
```

The output becomes:

```txt
[REDACTED]
```

## Java And Go Parity

There are two implementations:

```txt
Go CLI
Java CLI
```

We added parity tests to make sure their business logic matches.

Test file:

```txt
parity_test.go
```

It does this:

```txt
start local API
run Go CLI
run Java CLI
compare JSON reports
compare each rule status
```

Covered scenarios:

```txt
x-apikey on /v1/permissions
Authorization bearer token on /users/123?id=123
```

This proves the Java and Go scanners match for important auth and BOLA flows.

## Where To Debug

In IntelliJ, use main class:

```txt
com.apisec.cli.ApiSec
```

Recommended breakpoints:

```txt
ScanCommand.call
ScannerEngine.run
ScannerEngine.evaluateRule
ScannerEngine.detectAuth
ScannerEngine.bolaSkipReason
Mutator.generate
Evaluator.assertion
Reporter.writeJson
WebhookClient.send
```

If you want to understand a scan, debug in this order:

```txt
1. ScanCommand.call
2. ScannerEngine.run
3. CurlParser.parse
4. ScannerEngine.execute
5. RuleLoader.loadFile
6. ScannerEngine.evaluateRule
7. Mutator.generate
8. Evaluator.assertion
9. Reporter.writeJson
10. WebhookClient.send
```

## Example Walkthrough

Command:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../apisec/rules/owasp-api-2023.json \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

What happens:

```txt
1. CLI receives scan command.
2. Config is loaded.
3. Curl is parsed.
4. Original request is sent with x-apikey.
5. Baseline response is saved.
6. OWASP rules are loaded.
7. BOLA path ID rules are skipped because no object ID exists.
8. Auth rule detects x-apikey.
9. Scanner removes x-apikey.
10. Mutated request is sent.
11. If API returns 200, auth rule fails.
12. Report is printed.
13. JSON report is written.
14. Webhook sends report if enabled.
```

## How To Explain To A Manager

Use this:

```txt
This Java CLI lets us run local defensive API security checks from a curl command.
It uses the same SecurityRuleGroup schema as the runtime Mongo rules.
It safely tests authentication, authorization, configuration, and response exposure issues.
It avoids common false positives by detecting actual auth credentials and object identifiers.
It exports a JSON report and can send that report back to the API Security service through a webhook.
We also have parity tests proving the Java and Go CLIs produce the same rule results for key flows.
```

## Current Limitations

The CLI currently:

```txt
scans one endpoint per command
does not crawl
does not brute force
does not exploit destructively by default
does not claim CVEs without product/version evidence
```

This is intentional for safe defensive testing.

## Build And Test

Build:

```sh
cd apisec-java
mvn clean package -DskipTests
```

Test:

```sh
cd apisec-java
mvn test
```

Run:

```sh
java -jar target/apisec-java-1.0.0.jar --help
```

Parity:

```sh
cd ..
go test -run TestGoJavaReportParity -count=1
```

## Mental Model

Remember this simple picture:

```txt
Original curl
   |
   v
Baseline response
   |
   v
Rules decide what to test
   |
   v
Safe changed requests
   |
   v
Compare responses
   |
   v
Findings and report
```

That is the whole scanner.
