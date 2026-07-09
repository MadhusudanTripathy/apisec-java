package com.apisec.cli;

import com.apisec.config.AppConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import picocli.CommandLine;
import picocli.CommandLine.*;

import java.util.concurrent.Callable;

@Command(name = "config", mixinStandardHelpOptions = true, description = "Manage config", subcommands = {ConfigCommand.InitCmd.class, ConfigCommand.ShowCmd.class})
public class ConfigCommand implements Runnable {
    public void run() {
        new CommandLine(this).usage(System.out);
    }

    @Command(name = "init", mixinStandardHelpOptions = true)
    static class InitCmd implements Callable<Integer> {
        public Integer call() throws Exception {
            AppConfig.initDefault();
            System.out.println("Config initialized: " + AppConfig.expand("~/.apisec/config.yaml"));
            return 0;
        }
    }

    @Command(name = "show", mixinStandardHelpOptions = true)
    static class ShowCmd implements Callable<Integer> {
        @Option(names = "--config")
        String config;
        @Option(names = "--rules-dir")
        String rulesDir;
        @Option(names = "--report-dir")
        String reportDir;

        public Integer call() throws Exception {
            AppConfig c = AppConfig.resolve(config, rulesDir, reportDir, null, null, null, null, null, null);
            System.out.println(new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(c));
            return 0;
        }
    }
}
