/*
 * Copyright 2017-2024 the original author or authors.
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

package io.spring.github.actions.artifactorydeploy.maven;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildModule;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableFileArtifact;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link MavenBuildModulesGenerator}.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 */
class MavenBuildModulesGeneratorTests {

	private MavenBuildModulesGenerator generator = new MavenBuildModulesGenerator();

	@TempDir
	File tempDir;

	@Test
	void getBuildModulesReturnsBuildModules() {
		List<DeployableArtifact> deployableArtifacts = new ArrayList<>();
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.pom"));
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.jar"));
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0-sources.jar"));
		deployableArtifacts.add(artifact("/com/example/bar/1.0.0/bar-1.0.0.pom"));
		deployableArtifacts.add(artifact("/com/example/bar/1.0.0/bar-1.0.0.jar"));
		deployableArtifacts.add(artifact("/com/example/bar/1.0.0/bar-1.0.0-sources.jar"));
		List<BuildModule> buildModules = this.generator.getBuildModules(deployableArtifacts);
		assertThat(buildModules).hasSize(2);
		assertThat(buildModules.get(0).id()).isEqualTo("com.example:foo:1.0.0");
		assertThat(buildModules.get(0).artifacts()).extracting(BuildArtifact::name)
			.containsExactly("foo-1.0.0.pom", "foo-1.0.0.jar", "foo-1.0.0-sources.jar");
		assertThat(buildModules.get(0).artifacts()).extracting(BuildArtifact::type)
			.containsExactly("pom", "jar", "java-source-jar");
		assertThat(buildModules.get(1).id()).isEqualTo("com.example:bar:1.0.0");
		assertThat(buildModules.get(1).artifacts()).extracting(BuildArtifact::name)
			.containsExactly("bar-1.0.0.pom", "bar-1.0.0.jar", "bar-1.0.0-sources.jar");
		assertThat(buildModules.get(1).artifacts()).extracting(BuildArtifact::type)
			.containsExactly("pom", "jar", "java-source-jar");
	}

	@Test
	void getBuildModulesWhenContainingSpecificExtensionsFiltersArtifacts() {
		List<DeployableArtifact> deployableArtifacts = new ArrayList<>();
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.pom"));
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.asc"));
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.md5"));
		deployableArtifacts.add(artifact("/com/example/foo/1.0.0/foo-1.0.0.sha"));
		List<BuildModule> buildModules = this.generator.getBuildModules(deployableArtifacts);
		assertThat(buildModules.get(0).artifacts()).extracting(BuildArtifact::name)
			.containsExactly("foo-1.0.0.pom", "foo-1.0.0.asc");
	}

	@Test
	void getBuildModulesWhenContainingUnexpectedLayoutReturnsEmptyList() {
		List<DeployableArtifact> deployableArtifacts = new ArrayList<>();
		deployableArtifacts.add(artifact("/foo-1.0.0.zip"));
		List<BuildModule> buildModules = this.generator.getBuildModules(deployableArtifacts);
		assertThat(buildModules).isEmpty();
	}

	private DeployableArtifact artifact(String path) {
		File artifact = new File(this.tempDir, path);
		artifact.getParentFile().mkdirs();
		try {
			Files.createFile(artifact.toPath());
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		return new DeployableFileArtifact(path, artifact, null, null);
	}

}
