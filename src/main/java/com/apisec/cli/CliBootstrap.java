package com.apisec.cli;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

final class CliBootstrap {
  private static final int MAX_LOG_FILES = 5;
  private static final DateTimeFormatter LOG_TS =
      DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS").withZone(ZoneOffset.UTC);
  private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);

  private CliBootstrap() {}

  static void initialize() {
    if (!INITIALIZED.compareAndSet(false, true)) return;
    configureLogging();
    printStartupBanner();
  }

  static Path logsDirectory(Path workingDirectory) {
    return workingDirectory.resolve("logs");
  }

  static void pruneOldLogs(Path logsDirectory, int keep) throws IOException {
    if (keep < 1 || !Files.exists(logsDirectory)) return;
    List<Path> logFiles;
    try (var stream = Files.list(logsDirectory)) {
      logFiles = stream
          .filter(path -> Files.isRegularFile(path) && path.getFileName().toString().startsWith("apisec_") && path.getFileName().toString().endsWith(".log"))
          .sorted(Comparator.comparing(CliBootstrap::lastModifiedOrEpoch).reversed())
          .toList();
    }
    for (int i = keep; i < logFiles.size(); i++) {
      Files.deleteIfExists(logFiles.get(i));
    }
  }

  private static Instant lastModifiedOrEpoch(Path path) {
    try {
      return Files.getLastModifiedTime(path).toInstant();
    } catch (IOException e) {
      return Instant.EPOCH;
    }
  }

  private static void configureLogging() {
    try {
      Path workingDirectory = Path.of("").toAbsolutePath().normalize();
      Path logsDirectory = logsDirectory(workingDirectory);
      Files.createDirectories(logsDirectory);
      Path logFile = logsDirectory.resolve("apisec_" + LOG_TS.format(Instant.now()) + ".log");
      OutputStream sharedLog = synchronizedStream(new BufferedOutputStream(Files.newOutputStream(logFile)));
      PrintStream originalOut = System.out;
      PrintStream originalErr = System.err;
      PrintStream teeOut = new PrintStream(new TeeOutputStream(originalOut, sharedLog), true, StandardCharsets.UTF_8);
      PrintStream teeErr = new PrintStream(new TeeOutputStream(originalErr, sharedLog), true, StandardCharsets.UTF_8);
      System.setOut(teeOut);
      System.setErr(teeErr);
      Runtime.getRuntime().addShutdownHook(new Thread(() -> closeQuietly(sharedLog), "apisec-log-close"));
      pruneOldLogs(logsDirectory, MAX_LOG_FILES);
    } catch (Exception ignored) {
    }
  }

  private static void printStartupBanner() {
    if (ProgressSupport.supportsLiveDashboard()) {
      return;
    }
    for (String line : ProgressSupport.asciiArtLines()) {
      System.err.println(line);
    }
    System.err.println();
  }

  private static OutputStream synchronizedStream(OutputStream delegate) {
    return new OutputStream() {
      @Override public synchronized void write(int b) throws IOException { delegate.write(b); }
      @Override public synchronized void write(byte[] b) throws IOException { delegate.write(b); }
      @Override public synchronized void write(byte[] b, int off, int len) throws IOException { delegate.write(b, off, len); }
      @Override public synchronized void flush() throws IOException { delegate.flush(); }
      @Override public synchronized void close() throws IOException { delegate.close(); }
    };
  }

  private static void closeQuietly(OutputStream outputStream) {
    try {
      outputStream.flush();
      outputStream.close();
    } catch (IOException ignored) {
    }
  }

  private static final class TeeOutputStream extends OutputStream {
    private final OutputStream first;
    private final OutputStream second;

    private TeeOutputStream(OutputStream first, OutputStream second) {
      this.first = first;
      this.second = second;
    }

    @Override public void write(int b) throws IOException {
      first.write(b);
      second.write(b);
    }

    @Override public void write(byte[] b) throws IOException {
      first.write(b);
      second.write(b);
    }

    @Override public void write(byte[] b, int off, int len) throws IOException {
      first.write(b, off, len);
      second.write(b, off, len);
    }

    @Override public void flush() throws IOException {
      first.flush();
      second.flush();
    }
  }
}
