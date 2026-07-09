# Native Image Build

This document explains how to build the Java CLI as a standalone native binary named `apisec`.

## What Native Image Gives You

The normal Java build creates:

```txt
target/apisec-java-1.0.0.jar
```

That requires Java to run:

```sh
java -jar target/apisec-java-1.0.0.jar --help
```

The native build creates:

```txt
target/apisec
```

That runs directly:

```sh
./target/apisec --help
```

## Requirement

You need GraalVM with `native-image`.

Check:

```sh
native-image --version
```

If that command is missing, your current JDK cannot build the native binary.

## Install GraalVM

### SDKMAN

```sh
sdk list java | grep -i graal
sdk install java <graalvm-version-from-list>
sdk use java <graalvm-version-from-list>
native-image --version
```

### Homebrew

```sh
brew install --cask graalvm-jdk
export JAVA_HOME=$(/usr/libexec/java_home | grep -i graal | head -1)
export PATH="$JAVA_HOME/bin:$PATH"
native-image --version
```

If `native-image` is still missing, use the GraalVM JDK shown by:

```sh
/usr/libexec/java_home -V
```

## Build

From the Java CLI project:

```sh
cd /Users/madhusudantripathy/Documents/apisec-java
mvn -Pnative -DskipTests package
```

Expected output:

```txt
target/apisec
```

## Test The Binary

```sh
./target/apisec --help
./target/apisec rules validate --file ../apisec/rules/owasp-api-2023.json
./target/apisec pull --tenant acme-team-dev
```

Run a scan:

```sh
./target/apisec scan curl \
  --rules ../apisec/rules/owasp-api-2023.json \
  http://localhost:9002/itorix/v1/permissions \
  -H 'x-apikey: test'
```

You can pass normal curl-style request arguments directly:

```sh
./target/apisec scan curl 'https://dev-api.apiwiz.io/itorix/v1/users/login' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/plain, */*' \
  --data-raw '{"loginId":"user@example.com","password":"[REDACTED]","workspaceId":"stage-data"}'
```

## Notes

The project includes GraalVM reflection metadata at:

```txt
src/main/resources/META-INF/native-image/com.apisec/apisec-java/reflect-config.json
```

This is needed because:

- Picocli reads command annotations.
- Jackson reads and writes rule/report model classes.
- Rule groups are deserialized from JSON at runtime.

## Common Errors

### `native-image: command not found`

GraalVM is not active in your shell.

Fix:

```sh
export JAVA_HOME=<path-to-graalvm>
export PATH="$JAVA_HOME/bin:$PATH"
native-image --version
```

### Reflection or JSON Mapping Errors

If native binary fails while reading rules/reports, update:

```txt
src/main/resources/META-INF/native-image/com.apisec/apisec-java/reflect-config.json
```

Add the model class that Jackson is trying to deserialize.

### Slow Build

Native-image builds can take a few minutes and use a lot of memory. That is normal.
