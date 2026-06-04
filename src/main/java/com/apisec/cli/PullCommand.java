package com.apisec.cli;

import com.apisec.config.AppConfig;
import com.apisec.rules.RuleLoader;
import com.apisec.rules.RuleModels.Group;
import com.fasterxml.jackson.databind.*;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Callable;

@Command(name = "pull", mixinStandardHelpOptions = true, description = "Download remote rule groups")
public class PullCommand implements Callable<Integer> {
  @Option(names="--source", required=true) String source;
  @Option(names="--token") String token;
  @Option(names="--config") String config;
  @Option(names="--rules-dir") String rulesDir;
  @Option(names="--overwrite", defaultValue="false") boolean overwrite;

  @Override public Integer call() throws Exception {
    AppConfig cfg = AppConfig.resolve(config, rulesDir, null, null, null, null, null, null, null, null);
    HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(source)).timeout(Duration.ofSeconds(cfg.scanner.timeoutSeconds)).GET();
    if (token != null && !token.isBlank()) b.header("Authorization", "Bearer " + token);
    HttpResponse<String> res = HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    if (res.statusCode() < 200 || res.statusCode() >= 300) throw new IllegalStateException("rules API returned " + res.statusCode());
    ObjectMapper mapper = new ObjectMapper();
    JsonNode root = mapper.readTree(res.body());
    List<Group> groups = new ArrayList<>();
    if (root.isArray()) for (JsonNode n: root) groups.add(mapper.treeToValue(n, Group.class));
    else if (root.has("ruleGroups") && root.get("ruleGroups").isArray()) for (JsonNode n: root.get("ruleGroups")) groups.add(mapper.treeToValue(n, Group.class));
    else groups.add(mapper.treeToValue(root, Group.class));
    Files.createDirectories(Path.of(cfg.rules.directory));
    for (Group g: groups) {
      RuleLoader.validate(g);
      Path out = Path.of(cfg.rules.directory, g.id + ".json");
      if (Files.exists(out) && !overwrite) {
        System.out.println("Skipped existing rule group: " + out);
        continue;
      }
      Files.writeString(out, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(g));
      System.out.println("Saved rule group: " + out);
    }
    return 0;
  }
}
