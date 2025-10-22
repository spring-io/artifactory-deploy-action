/*
 * Copyright 2017-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.spring.github.actions.artifactorydeploy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import org.springframework.boot.test.json.BasicJsonTester;
import org.springframework.boot.test.json.JsonContent;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link ArtifactoryDeploy} that invoke its main method.
 *
 * @author Andy Wilkinson
 */
@Testcontainers(disabledWithoutDocker = true)
class ArtifactoryDeployIntegrationTests {

	@Container
	static GenericContainer<?> container = new GenericContainer<>("docker.bintray.io/jfrog/artifactory-oss:7.12.10")
		.waitingFor(Wait.forHttp("/artifactory/api/system/ping").withStartupTimeout(Duration.ofMinutes(15)))
		.withExposedPorts(8081);

	@Test
	void deploy(@TempDir File temp) throws IOException {
		File example = new File(temp, "com/example/module/1.0.0");
		example.mkdirs();
		Files.writeString(new File(example, "module-1.0.0.jar").toPath(), "jar-file-content");
		Files.writeString(new File(example, "module-1.0.0.pom").toPath(), "pom-file-content");
		ArtifactoryDeploy.main(new String[] {
				String.format("--artifactory.server.uri=http://%s:%s/artifactory", container.getHost(),
						container.getFirstMappedPort()),
				"--artifactory.server.username=admin", "--artifactory.server.password=password",
				"--artifactory.vcs.revision=b8993e365706816aba4f25717851a18c9cd0d873",
				"--artifactory.deploy.repository=example-repo-local", "--artifactory.deploy.build.number=12",
				"--artifactory.deploy.build.name=integration-test", "--artifactory.deploy.folder=" + temp,
				"--artifactory.deploy.threads=2" });
		RestTemplate rest = new RestTemplateBuilder().basicAuthentication("admin", "password")
			.rootUri("http://%s:%s/artifactory/".formatted(container.getHost(), container.getFirstMappedPort()))
			.build();
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.jar", String.class))
			.isEqualTo("jar-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.pom", String.class))
			.isEqualTo("pom-file-content");
		JsonContent<?> buildInfoJson = new BasicJsonTester(getClass())
			.from(rest.getForObject("/api/build/integration-test/12", String.class));
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.name").isEqualTo("integration-test");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.number").isEqualTo("12");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.buildAgent.name").isEqualTo("Artifactory Action");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.agent.name").isEqualTo("GitHub Actions");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.vcs").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.vcs.[0].revision")
			.isEqualTo("b8993e365706816aba4f25717851a18c9cd0d873");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules.[0].artifacts").hasSize(2);
	}

	@Test
	void deployWithArtifactProeprties(@TempDir File temp) throws IOException {
		File example = new File(temp, "com/example/example-docs/1.0.0");
		example.mkdirs();
		Files.writeString(new File(example, "example-docs-1.0.0.zip").toPath(), "jar-file-content");
		Files.writeString(new File(example, "example-docs-1.0.0.pom").toPath(), "pom-file-content");
		ArtifactoryDeploy.main(new String[] {
				String.format("--artifactory.server.uri=http://%s:%s/artifactory", container.getHost(),
						container.getFirstMappedPort()),
				"--artifactory.server.username=admin", "--artifactory.server.password=password",
				"--artifactory.vcs.revision=b8993e365706816aba4f25717851a18c9cd0d873",
				"--artifactory.deploy.repository=example-repo-local", "--artifactory.deploy.build.number=13",
				"--artifactory.deploy.build.name=integration-test", "--artifactory.deploy.folder=" + temp,
				"--artifactory.deploy.threads=2",
				"--artifactory.deploy.artifact-properties=/**/example-docs-*.zip::zip.type=docs,zip.deployed=false" });
		RestTemplate rest = new RestTemplateBuilder().basicAuthentication("admin", "password")
			.rootUri("http://%s:%s/artifactory/".formatted(container.getHost(), container.getFirstMappedPort()))
			.build();
		assertThat(rest.getForObject("/example-repo-local/com/example/example-docs/1.0.0/example-docs-1.0.0.zip",
				String.class))
			.isEqualTo("jar-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/example-docs/1.0.0/example-docs-1.0.0.pom",
				String.class))
			.isEqualTo("pom-file-content");
		String buildInfo = rest.getForObject("/api/build/integration-test/13", String.class);
		BasicJsonTester jsonTester = new BasicJsonTester(getClass());
		JsonContent<?> buildInfoJson = jsonTester.from(buildInfo);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.name").isEqualTo("integration-test");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.number").isEqualTo("13");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.buildAgent.name").isEqualTo("Artifactory Action");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.agent.name").isEqualTo("GitHub Actions");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.vcs").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.vcs.[0].revision")
			.isEqualTo("b8993e365706816aba4f25717851a18c9cd0d873");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules.[0].artifacts").hasSize(2);
		String zipProperties = rest.getForObject(
				"/api/storage/example-repo-local/com/example/example-docs/1.0.0/example-docs-1.0.0.zip?properties",
				String.class);
		JsonContent<?> zipPropertiesJson = jsonTester.from(zipProperties);
		assertThat(zipPropertiesJson).extractingJsonPathMapValue("properties")
			.containsOnlyKeys("build.name", "build.number", "build.timestamp", "zip.deployed", "zip.type");
		assertThat(zipPropertiesJson).extractingJsonPathArrayValue("properties['zip.deployed']")
			.containsExactly("false");
		assertThat(zipPropertiesJson).extractingJsonPathArrayValue("properties['zip.type']").containsExactly("docs");
		String pomProperties = rest.getForObject(
				"/api/storage/example-repo-local/com/example/example-docs/1.0.0/example-docs-1.0.0.pom?properties",
				String.class);
		JsonContent<?> pomPropertiesJson = jsonTester.from(pomProperties);
		assertThat(pomPropertiesJson).extractingJsonPathMapValue("properties")
			.containsOnlyKeys("build.name", "build.number", "build.timestamp");
	}

	@Test
	void deployWithSignatures(@TempDir File temp) throws IOException {
		File example = new File(temp, "com/example/module/1.0.0");
		example.mkdirs();
		Files.writeString(new File(example, "module-1.0.0.jar").toPath(), "jar-file-content");
		Files.writeString(new File(example, "module-1.0.0.pom").toPath(), "pom-file-content");
		ArtifactoryDeploy.main(new String[] {
				String.format("--artifactory.server.uri=http://%s:%s/artifactory", container.getHost(),
						container.getFirstMappedPort()),
				"--artifactory.server.username=admin", "--artifactory.server.password=password",
				"--artifactory.vcs.revision=b8993e365706816aba4f25717851a18c9cd0d873",
				"--artifactory.deploy.repository=example-repo-local", "--artifactory.deploy.build.number=14",
				"--artifactory.deploy.build.name=integration-test", "--artifactory.deploy.folder=" + temp,
				"--artifactory.deploy.threads=2",
				"--artifactory.signing.key=" + Files.readString(Path.of("src", "test", "resources", "io", "spring",
						"github", "actions", "artifactorydeploy", "openpgp", "test-private.txt")),
				"--artifactory.signing.passphrase=password" });
		RestTemplate rest = new RestTemplateBuilder().basicAuthentication("admin", "password")
			.rootUri("http://%s:%s/artifactory/".formatted(container.getHost(), container.getFirstMappedPort()))
			.build();
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.jar", String.class))
			.isEqualTo("jar-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.pom", String.class))
			.isEqualTo("pom-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.jar.asc", byte[].class))
			.isNotEmpty();
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.pom.asc", byte[].class))
			.isNotEmpty();
		String buildInfo = rest.getForObject("/api/build/integration-test/14", String.class);
		BasicJsonTester jsonTester = new BasicJsonTester(getClass());
		JsonContent<?> buildInfoJson = jsonTester.from(buildInfo);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.name").isEqualTo("integration-test");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.number").isEqualTo("14");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.buildAgent.name").isEqualTo("Artifactory Action");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.agent.name").isEqualTo("GitHub Actions");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.vcs").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.vcs.[0].revision")
			.isEqualTo("b8993e365706816aba4f25717851a18c9cd0d873");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules.[0].artifacts").hasSize(4);
	}

	@Test
	void deployWithSignaturesFromSubkey(@TempDir File temp) throws IOException {
		File example = new File(temp, "com/example/module/1.0.0");
		example.mkdirs();
		Files.writeString(new File(example, "module-1.0.0.jar").toPath(), "jar-file-content");
		Files.writeString(new File(example, "module-1.0.0.pom").toPath(), "pom-file-content");
		ArtifactoryDeploy.main(new String[] {
				String.format("--artifactory.server.uri=http://%s:%s/artifactory", container.getHost(),
						container.getFirstMappedPort()),
				"--artifactory.server.username=admin", "--artifactory.server.password=password",
				"--artifactory.vcs.revision=b8993e365706816aba4f25717851a18c9cd0d873",
				"--artifactory.deploy.repository=example-repo-local", "--artifactory.deploy.build.number=15",
				"--artifactory.deploy.build.name=integration-test", "--artifactory.deploy.folder=" + temp,
				"--artifactory.deploy.threads=2",
				"--artifactory.signing.key=" + Files.readString(Path.of("src", "test", "resources", "io", "spring",
						"github", "actions", "artifactorydeploy", "openpgp", "test-private-subkey.txt")),
				"--artifactory.signing.passphrase=password", "--artifactory.signing.key-id=C3E2E826" });

		RestTemplate rest = new RestTemplateBuilder().basicAuthentication("admin", "password")
			.rootUri("http://%s:%s/artifactory/".formatted(container.getHost(), container.getFirstMappedPort()))
			.build();
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.jar", String.class))
			.isEqualTo("jar-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.pom", String.class))
			.isEqualTo("pom-file-content");
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.jar.asc", byte[].class))
			.isNotEmpty();
		assertThat(rest.getForObject("/example-repo-local/com/example/module/1.0.0/module-1.0.0.pom.asc", byte[].class))
			.isNotEmpty();
		String buildInfo = rest.getForObject("/api/build/integration-test/15", String.class);
		BasicJsonTester jsonTester = new BasicJsonTester(getClass());
		JsonContent<?> buildInfoJson = jsonTester.from(buildInfo);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.name").isEqualTo("integration-test");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.number").isEqualTo("15");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.buildAgent.name").isEqualTo("Artifactory Action");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.agent.name").isEqualTo("GitHub Actions");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.vcs").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.vcs.[0].revision")
			.isEqualTo("b8993e365706816aba4f25717851a18c9cd0d873");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules.[0].artifacts").hasSize(4);
	}

}
