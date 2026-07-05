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

package io.spring.artifactory.deploy.artifactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import io.spring.artifactory.deploy.Deployer;
import io.spring.artifactory.deploy.artifactory.payload.Promotion;
import io.spring.artifactory.deploy.io.DirectoryScanner;
import io.spring.artifactory.deploy.system.Logger;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import org.springframework.boot.test.json.BasicJsonTester;
import org.springframework.boot.test.json.JsonContent;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Integration tests for {@link HttpArtifactory}.
 *
 * @author Phillip Webb
 */
@Testcontainers(disabledWithoutDocker = true)
class ArtifactoryIntegrationTests {

	@Container
	static ArtifactoryContainer container = new ArtifactoryContainer();

	@Test
	void deploy(@TempDir Path temp) throws IOException {
		Path example = temp.resolve("com/example/module/1.0.0");
		Files.createDirectories(example);
		Files.writeString(example.resolve("module-1.0.0.jar"), "jar-file-content");
		Files.writeString(example.resolve("module-1.0.0.pom"), "pom-file-content");
		Artifactory artifactory = container.getArtifactory();
		Deployer deployer = new Deployer(Logger.console(true), artifactory, new DirectoryScanner(),
				container.getBaseUrl(), 3);
		deployer.deploy("libs-release-local", "12", "integration-test", null, null, null, temp, null, null);
		assertThat(container.getRestClient()
			.get()
			.uri("/libs-release-local/com/example/module/1.0.0/module-1.0.0.jar")
			.retrieve()
			.body(String.class)).isEqualTo("jar-file-content");
		assertThat(container.getRestClient()
			.get()
			.uri("/libs-release-local/com/example/module/1.0.0/module-1.0.0.pom")
			.retrieve()
			.body(String.class)).isEqualTo("pom-file-content");
		JsonContent<?> buildInfoJson = new BasicJsonTester(getClass()).from(container.getRestClient()
			.get()
			.uri("/api/build/integration-test/12")
			.accept(MediaType.APPLICATION_JSON)
			.retrieve()
			.body(String.class));
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.name").isEqualTo("integration-test");
		assertThat(buildInfoJson).extractingJsonPathValue("buildInfo.number").isEqualTo("12");
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules").hasSize(1);
		assertThat(buildInfoJson).extractingJsonPathArrayValue("buildInfo.modules.[0].artifacts").hasSize(2);
	}

	@Test
	@Disabled("requires a pro license")
	void promote(@TempDir Path temp) throws IOException {
		Path example = temp.resolve("com/example/module/2.0.0");
		Files.createDirectories(example);
		Files.writeString(example.resolve("module-2.0.0.jar"), "jar-file-content-2");
		Files.writeString(example.resolve("module-2.0.0.pom"), "pom-file-content-2");
		Artifactory artifactory = container.getArtifactory();
		Deployer deployer = new Deployer(Logger.console(true), artifactory, new DirectoryScanner(),
				container.getBaseUrl(), 3);
		deployer.deploy("libs-release-local", "22", "integration-test", null, null, null, temp, null, null);
		assertThatNoException().isThrownBy(() -> container.getRestClient()
			.get()
			.uri("/libs-release-local/com/example/module/2.0.0/module-2.0.0.jar")
			.retrieve()
			.body(String.class));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(() -> container.getRestClient()
			.get()
			.uri("/libs-test-local/com/example/module/2.0.0/module-2.0.0.jar")
			.retrieve()
			.body(String.class));
		artifactory.promoteBuild("integration-test", "22", new Promotion("libs-release-local", "libs-test-local"));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(() -> container.getRestClient()
			.get()
			.uri("/libs-release-local/com/example/module/2.0.0/module-2.0.0.jar")
			.retrieve()
			.body(String.class));
		assertThatNoException().isThrownBy(() -> container.getRestClient()
			.get()
			.uri("/libs-test-local/com/example/module/2.0.0/module-2.0.0.jar")
			.retrieve()
			.body(String.class));
	}

}
