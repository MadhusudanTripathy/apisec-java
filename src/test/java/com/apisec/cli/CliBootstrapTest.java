package com.apisec.cli;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CliBootstrapTest {

  @Test void retainsOnlyLatestFiveLogs() throws Exception {
    Path logsDir = Files.createTempDirectory("apisec-cli-logs");
    for (int i = 1; i <= 7; i++) {
      Path log = logsDir.resolve("apisec_20260717_10000" + i + "_000.log");
      Files.writeString(log, "run-" + i);
      Files.setLastModifiedTime(log, java.nio.file.attribute.FileTime.from(Instant.parse("2026-07-17T10:00:0" + i + "Z")));
    }

    CliBootstrap.pruneOldLogs(logsDir, 5);

    List<String> names;
    try (var stream = Files.list(logsDir)) {
      names = stream
          .map(path -> path.getFileName().toString())
          .sorted()
          .toList();
    }

    assertEquals(5, names.size());
    assertEquals(List.of(
        "apisec_20260717_100003_000.log",
        "apisec_20260717_100004_000.log",
        "apisec_20260717_100005_000.log",
        "apisec_20260717_100006_000.log",
        "apisec_20260717_100007_000.log"
    ), names);
  }
}
