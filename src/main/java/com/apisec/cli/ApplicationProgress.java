package com.apisec.cli;

import com.apisec.engine.ScannerEngine.ProgressSink;
import com.apisec.report.ReportModels.Report;

interface ApplicationProgress extends ProgressSink, AutoCloseable {
  void resourceStarted(int index, int total, String method, String target, String operationId);
  void resourceSkipped(String reason);
  void resourceCompleted(Report report);
  void resourceFailed(String reason);
}
