package com.apisec.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "apisec", mixinStandardHelpOptions = true, version = "apisec-java 1.0.0",
        subcommands = {ScanCommand.class, PullCommand.class, RulesCommand.class, ConfigCommand.class})
public class ApiSec implements Runnable {
    public static void main(String[] args) {
        System.exit(new CommandLine(new ApiSec()).execute(args));
    }

    @Override
    public void run() {
        new CommandLine(this).usage(System.out);
    }
}
