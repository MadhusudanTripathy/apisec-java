# Build

```sh
cd apisec-java
mvn test
mvn package
```

## Native Binary

Install GraalVM JDK 17 or newer with `native-image`, then point `JAVA_HOME` to GraalVM.

On macOS with SDKMAN:

```sh
sdk install java 17.0.12-graal
sdk use java 17.0.12-graal
native-image --version
```

Or with Homebrew:

```sh
brew install --cask graalvm-jdk
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export PATH="$JAVA_HOME/bin:$PATH"
native-image --version
```

Build the native executable:

```sh
mvn -Pnative -DskipTests package
```

Output:

```txt
target/apisec
```

That command produces a native binary for the current host OS only.

### Linux executable from macOS

If you are building on macOS and need a Linux binary for Ubuntu or another Linux host, use the Docker-based Linux native build:

```sh
./scripts/build-linux-native.sh amd64
```

For Linux ARM64:

```sh
./scripts/build-linux-native.sh arm64
```

Outputs:

```txt
dist/linux-amd64/apisec
dist/linux-arm64/apisec
```

This requires Docker to be running locally.

Run it:

```sh
./target/apisec --help
./target/apisec pull --tenant acme-team-dev
./target/apisec scan curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'
```

## Run

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules ../apisec/rules/api2-broken-authentication.json \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

## Configure Once

The Java CLI loads exactly one properties file from the current working directory:

```txt
./config.properties
```

Create it with:

```sh
java -jar target/apisec-java-1.0.0.jar config init
```

Example:

```properties
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

rules.directory=rules
rules.activeGroups=api1-broken-object-level-authorization,api2-broken-authentication,api3-broken-object-property-level-authorization,api4-unrestricted-resource-consumption,api5-broken-function-level-authorization,api6-unrestricted-access-to-sensitive-business-flows,api7-server-side-request-forgery,api8-security-misconfiguration,api9-improper-inventory-management,api10-unsafe-consumption-of-apis
rules.pull.enabled=true
rules.pull.sourceUrl=http://localhost:8073/v1/apiwiz-api-security/cli/pull/rule-group
rules.pull.tokenEnv=APISEC_RULES_TOKEN
rules.pull.tenant=acme-team-dev

reports.directory=reports
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
java -jar target/apisec-java-1.0.0.jar scan curl \
  http://localhost:9002/itorix/v1/permissions \
  -H 'x-apikey: test'
```

The old wrapped form is still supported:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --curl "curl http://localhost:9002/itorix/v1/permissions -H 'x-apikey: test'"
```

When the rules directory is configured, `--rules` may also be a group id:

```sh
java -jar target/apisec-java-1.0.0.jar scan \
  --rules-dir ../apisec/rules \
  --rules api2-broken-authentication \
  --curl-file request.curl
```

Use concise default output, or expand it:

```sh
java -jar target/apisec-java-1.0.0.jar scan --show-passed --show-skipped --curl-file request.curl
java -jar target/apisec-java-1.0.0.jar scan --verbose --curl-file request.curl
```

## Validate Rules

```sh
java -jar target/apisec-java-1.0.0.jar rules validate --file ../apisec/rules/owasp-api-2023-backup.json
```

## Pull Rules

If `rules.pull.sourceUrl` and `rules.pull.tenant` are configured, pull needs no source flags:

```sh
java -jar target/apisec-java-1.0.0.jar pull
```

This sends:

```txt
GET http://localhost:8073/v1/apiwiz-api-security/cli/pull/rule-group
tenant: acme-team-dev
```

You can still override the configured source or tenant:

```sh
java -jar target/apisec-java-1.0.0.jar pull \
  --source http://localhost:8073/v1/apiwiz-api-security/cli/pull/rule-group \
  --tenant acme-team-dev
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
  --rules ../apisec/rules/api2-broken-authentication.json \
  --curl-file request.curl \
  --webhook http://localhost:9002/v1/apiwiz-api-security/cli/webhook \
  --webhook-tenant my-tenant \
  --webhook-secret "$APISEC_CLI_WEBHOOK_SECRET"
```

The CLI sends:

- `tenant`
- `X-ApiSec-Scan-Id`
- `X-ApiSec-Signature: sha256=<hmac>` when `--webhook-secret` is provided

To Build Exe:
- `cd /Users/madhusudantripathy/Documents/apisec-java`
- `JAVA_HOME="/Library/Java/JavaVirtualMachines/graalvm-jdk-17.0.12+8.1/Contents/Home" \
  PATH="/Library/Java/JavaVirtualMachines/graalvm-jdk-17.0.12+8.1/Contents/Home/bin:$PATH" \
  mvn -Pnative -DskipTests package`
