package com.apisec.cli;

import com.apisec.config.AppConfig;
import com.apisec.rules.*;
import com.apisec.rules.RuleModels.Group;
import picocli.CommandLine;
import picocli.CommandLine.*;

import java.nio.file.*;
import java.util.concurrent.Callable;

@Command(name = "rules", mixinStandardHelpOptions = true, description = "Manage rule groups", subcommands = {RulesCommand.ListCmd.class, RulesCommand.ShowCmd.class, RulesCommand.ValidateCmd.class})
public class RulesCommand implements Runnable {
    public void run() {
        new CommandLine(this).usage(System.out);
    }

    @Command(name = "list", mixinStandardHelpOptions = true)
    static class ListCmd implements Callable<Integer> {
        @Option(names = "--rules-dir")
        String rulesDir;

        public Integer call() throws Exception {
            AppConfig c = AppConfig.resolve(rulesDir, null, null, null, null, null, null, null);
            for (Group g : RuleLoader.loadDir(c.rules.directory, c.rules.activeGroups))
                System.out.printf("%s\t%s\t%d rules\t%s%n", RuleLoader.displayKey(g), g.version(), g.rules.size(), g.name);
            return 0;
        }
    }

    @Command(name = "show", mixinStandardHelpOptions = true)
    static class ShowCmd implements Callable<Integer> {
        @Option(names = "--id", required = true)
        String id;
        @Option(names = "--rules-dir")
        String rulesDir;

        public Integer call() throws Exception {
            AppConfig c = AppConfig.resolve(rulesDir, null, null, null, null, null, null, null);
            for (Group g : RuleLoader.loadDir(c.rules.directory, java.util.List.of()))
                if (id.equals(g.id) || id.equals(g.name) || id.equals(RuleLoader.displayKey(g))) {
                    System.out.printf("%s%nVersion: %s%nRules: %d%n%s%n", g.name, g.version(), g.rules.size(), g.description);
                    return 0;
                }
            throw new IllegalArgumentException("rule group not found: " + id);
        }
    }

    @Command(name = "validate", mixinStandardHelpOptions = true)
    static class ValidateCmd implements Callable<Integer> {
        @Option(names = "--file", required = true)
        Path file;

        public Integer call() throws Exception {
            Group g = RuleLoader.loadFile(file);
            System.out.printf("{%n  \"name\": \"%s\",%n  \"rules\": %d,%n  \"valid\": true,%n  \"version\": \"%s\"%n}%n", g.name, g.rules.size(), g.version());
            return 0;
        }
    }
}
