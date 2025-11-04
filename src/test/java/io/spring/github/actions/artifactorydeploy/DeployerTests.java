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
import java.net.URI;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy.ArtifactProperties;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy.Build;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Server;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Vcs;
import io.spring.github.actions.artifactorydeploy.artifactory.Artifactory;
import io.spring.github.actions.artifactorydeploy.artifactory.Artifactory.BuildRun;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildModule;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.io.DirectoryScanner;
import io.spring.github.actions.artifactorydeploy.io.FileSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import org.springframework.util.FileCopyUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link Deployer}.
 *
 * @author Madhura Bhave
 * @author Phillip Webb
 * @author Andy Wilkinson
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DeployerTests {

	private static final byte[] NO_BYTES = {};

	@TempDir
	File tempDir;

	@Mock
	private Artifactory artifactory;

	@Mock
	private DirectoryScanner directoryScanner;

	@Captor
	ArgumentCaptor<BuildRun> buildRunCaptor;

	@Captor
	private ArgumentCaptor<DeployableArtifact> artifactCaptor;

	@Test
	void deployWhenFolderIsEmptyThrowsException() {
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of());
		assertThatIllegalStateException().isThrownBy(() -> deployer(1).deploy())
			.withMessage("No artifacts found in empty directory '%s'".formatted(this.tempDir));
	}

	@Test
	void deployWhenScanningFindsNoFilesThrowsException() throws IOException {
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of());
		Files.createFile(new File(this.tempDir, "file").toPath());
		assertThatIllegalStateException().isThrownBy(() -> deployer(1).deploy())
			.withMessage("No artifacts found to deploy");
	}

	@Test
	void deployAddsBuildRun() throws Exception {
		File artifact = new File(this.tempDir, "com/example/foo/0.0.1/foo-0.0.1.jar");
		artifact.getParentFile().mkdirs();
		Files.createFile(artifact.toPath());
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact));
		deployer(1234).deploy();
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		BuildRun buildRun = this.buildRunCaptor.getValue();
		assertThat(buildRun.number()).isEqualTo(1234);
		assertThat(buildRun.modules()).hasSize(1);
		assertThat(buildRun.modules()).first().satisfies((module) -> {
			assertThat(module.id()).isEqualTo("com.example:foo:0.0.1");
			assertThat(module.artifacts()).hasSize(1).first().satisfies((moduleArtifact) -> {
				assertThat(moduleArtifact.name()).isEqualTo("foo-0.0.1.jar");
				assertThat(moduleArtifact.type()).isEqualTo("jar");
			});
		});
	}

	@Test
	void deployWithProjectAddsBuildRunToProject() throws Exception {
		File artifact = new File(this.tempDir, "com/example/foo/0.0.1/foo-0.0.1.jar");
		artifact.getParentFile().mkdirs();
		Files.createFile(artifact.toPath());
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact));
		deployer(1234, "my-project").deploy();
		verify(this.artifactory).addBuildRun(eq("my-project"), eq("my-build"), this.buildRunCaptor.capture());
		BuildRun buildRun = this.buildRunCaptor.getValue();
		assertThat(buildRun.number()).isEqualTo(1234);
		assertThat(buildRun.modules()).hasSize(1).first().satisfies((module) -> {
			assertThat(module.id()).isEqualTo("com.example:foo:0.0.1");
			assertThat(module.artifacts()).hasSize(1).first().satisfies((moduleArtifact) -> {
				assertThat(moduleArtifact.name()).isEqualTo("foo-0.0.1.jar");
				assertThat(moduleArtifact.type()).isEqualTo("jar");
			});
		});
	}

	@Test
	void deployDeploysArtifacts() throws Exception {
		File artifact = new File(this.tempDir, "com/example/foo/0.0.1/foo-0.0.1.jar");
		artifact.getParentFile().mkdirs();
		Files.createFile(artifact.toPath());
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact));
		deployer(1234).deploy();
		verify(this.artifactory).deploy(eq("libs-example-local"), this.artifactCaptor.capture());
		DeployableArtifact deployed = this.artifactCaptor.getValue();
		assertThat(deployed.getPath()).isEqualTo("/com/example/foo/0.0.1/foo-0.0.1.jar");
		assertThat(deployed.getProperties()).containsEntry("build.name", "my-build")
			.containsEntry("build.number", "1234")
			.containsKey("build.timestamp");
	}

	@Test
	void deployDeploysMultipleArtifactsInBatches() throws Exception {
		List<File> files = new ArrayList<>();
		File foos = createStructure(this.tempDir, "com", "example", "foo", "0.0.1");
		File bars = createStructure(this.tempDir, "com", "example", "bar", "0.0.1");
		File bazs = createStructure(this.tempDir, "com", "example", "baz", "0.0.1");
		files.add(new File(foos, "foo-0.0.1.jar"));
		files.add(new File(bars, "bar-0.0.1.jar"));
		files.add(new File(bazs, "baz-0.0.1.jar"));
		files.add(new File(foos, "foo-0.0.1.pom"));
		files.add(new File(bars, "bar-0.0.1.pom"));
		files.add(new File(bazs, "baz-0.0.1.pom"));
		files.add(new File(foos, "foo-0.0.1-javadoc.jar"));
		files.add(new File(bars, "bar-0.0.1-javadoc.jar"));
		files.add(new File(bazs, "baz-0.0.1-javadoc.jar"));
		files.add(new File(foos, "foo-0.0.1-sources.jar"));
		files.add(new File(bars, "bar-0.0.1-sources.jar"));
		files.add(new File(bazs, "baz-0.0.1-sources.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(any())).willReturn(FileSet.of(files));
		Set<Thread> usedThreads = new HashSet<>();
		willAnswer((invocation) -> {
			usedThreads.add(Thread.currentThread());
			return null;
		}).given(this.artifactory).deploy(eq("libs-example-local"), any(DeployableArtifact.class));
		int threads = 2;
		deployer(1234, 2).deploy();
		verify(this.artifactory, times(12)).deploy(eq("libs-example-local"), this.artifactCaptor.capture());
		assertThat(usedThreads).hasSizeLessThanOrEqualTo(threads);
		assertThat(usedThreads.stream().map(Thread::getName)).allSatisfy((name) -> name.startsWith("deployer-"));
		List<DeployableArtifact> values = this.artifactCaptor.getAllValues();
		for (int i = 0; i < 3; i++) {
			assertThat(values.get(i).getPath()).doesNotContain("javadoc", "sources").endsWith(".jar");
		}
		for (int i = 3; i < 6; i++) {
			assertThat(values.get(i).getPath()).endsWith(".pom");
		}
		for (int i = 6; i < 12; i++) {
			assertThat(values.get(i).getPath())
				.matches((path) -> path.endsWith("-javadoc.jar") || path.endsWith("-sources.jar"));
		}
	}

	@Test
	void deployWhenHasArtifactPropertiesDeploysWithAdditionalProperties() throws Exception {
		File artifact = new File(this.tempDir, "com/example/foo/0.0.1/foo-0.0.1.jar");
		artifact.getParentFile().mkdirs();
		Files.createFile(artifact.toPath());
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact));
		deployer(1234,
				new ArtifactProperties(List.of("/**/foo-0.0.1.jar"), Collections.emptyList(), Map.of("foo", "bar")))
			.deploy();
		verify(this.artifactory).deploy(eq("libs-example-local"), this.artifactCaptor.capture());
		DeployableArtifact deployed = this.artifactCaptor.getValue();
		assertThat(deployed.getPath()).isEqualTo("/com/example/foo/0.0.1/foo-0.0.1.jar");
		assertThat(deployed.getProperties()).containsEntry("build.name", "my-build")
			.containsEntry("build.number", "1234")
			.containsKey("build.timestamp")
			.containsEntry("foo", "bar");
	}

	@Test
	void deployFiltersChecksumFiles() throws IOException {
		File fooModule = new File(this.tempDir, "com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule, "foo-0.0.1.jar"));
		files.add(new File(fooModule, "foo-0.0.1.md5"));
		files.add(new File(fooModule, "foo-0.0.1.sha1"));
		files.add(new File(fooModule, "foo-0.0.1.sha256"));
		files.add(new File(fooModule, "foo-0.0.1.sha512"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir)).willReturn(FileSet.of(files));
		deployer(1234).deploy();
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployFiltersOutMavenMetadataFiles() throws IOException {
		File fooModule = new File(this.tempDir, "com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.getParentFile(), "maven-metadata.xml"));
		files.add(new File(fooModule, "foo-0.0.1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir)).willReturn(FileSet.of(files));
		deployer(1234).deploy();
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployFiltersOutMavenMetadataLocalFiles() throws IOException {
		File fooModule = new File(this.tempDir, "com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.getParentFile(), "maven-metadata-local.xml"));
		files.add(new File(fooModule, "foo-0.0.1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir)).willReturn(FileSet.of(files));
		deployer(1234).deploy();
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployWithSnapshotTimestampArtifactChangesArtifactPath() throws IOException {
		File fooModule = new File(this.tempDir, "com/example/foo/0.0.1-SNAPSHOT");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule, "foo-0.0.1-20240305.110926-1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir)).willReturn(FileSet.of(files));
		deployer(1234).deploy();
		verify(this.artifactory).deploy(eq("libs-example-local"), this.artifactCaptor.capture());
		DeployableArtifact artifact = this.artifactCaptor.getValue();
		assertThat(artifact.getPath()).isEqualTo("/com/example/foo/0.0.1-SNAPSHOT/foo-0.0.1-SNAPSHOT.jar");
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1)
			.first()
			.satisfies((module) -> assertThat(module.artifacts()).hasSize(1).first().satisfies((moduleArtifact) -> {
				assertThat(moduleArtifact.type()).isEqualTo("jar");
				assertThat(moduleArtifact.name()).isEqualTo("foo-0.0.1-SNAPSHOT.jar");
			}));
	}

	@Test
	void deployWithSnapshotTimestampArtifactRemovesDuplicates() throws IOException {
		File fooModule = new File(this.tempDir, "com/example/foo/0.0.1-SNAPSHOT");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule, "foo-0.0.1-20240305.110926-1.jar"));
		files.add(new File(fooModule, "foo-0.0.1-20240305.110926-2.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir)).willReturn(FileSet.of(files));
		deployer(1234).deploy();
		verify(this.artifactory).deploy(eq("libs-example-local"), this.artifactCaptor.capture());
		DeployableArtifact artifact = this.artifactCaptor.getValue();
		assertThat(artifact.getPath()).isEqualTo("/com/example/foo/0.0.1-SNAPSHOT/foo-0.0.1-SNAPSHOT.jar");
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1)
			.first()
			.satisfies((module) -> assertThat(module.artifacts()).hasSize(1).first().satisfies((moduleArtifact) -> {
				assertThat(moduleArtifact.type()).isEqualTo("jar");
				assertThat(moduleArtifact.name()).isEqualTo("foo-0.0.1-SNAPSHOT.jar");
			}));
	}

	private File createStructure(File directory, String... paths) {
		File dir = new File(directory, String.join("/", paths));
		dir.mkdirs();
		return dir;
	}

	private void createEmptyFiles(List<File> files) throws IOException {
		for (File file : files) {
			FileCopyUtils.copy(NO_BYTES, file);
		}
	}

	private Deployer deployer(int buildNumber) {
		return deployer(buildNumber, null, null, 1);
	}

	private Deployer deployer(int buildNumber, int threads) {
		return deployer(buildNumber, null, null, threads);
	}

	private Deployer deployer(int buildNumber, ArtifactProperties artifactProperties) {
		return deployer(buildNumber, null, artifactProperties);
	}

	private Deployer deployer(int buildNumber, String project) {
		return deployer(buildNumber, project, null);
	}

	private Deployer deployer(int buildNumber, String project, ArtifactProperties artifactProperties) {
		return deployer(buildNumber, project, artifactProperties, 1);
	}

	private Deployer deployer(int buildNumber, String project, ArtifactProperties artifactProperties, int threads) {
		return new Deployer(createProperties(buildNumber, project, artifactProperties, threads), this.artifactory,
				this.directoryScanner);
	}

	private ArtifactoryDeployProperties createProperties(int buildNumber, String project,
			ArtifactProperties artifactProperties, int threads) {
		return new ArtifactoryDeployProperties(new Server(URI.create("https://repo.example.com"), "alice", "secret"),
				null, new Vcs("b8993e365706816aba4f25717851a18c9cd0d873"),
				new Deploy(project, this.tempDir.getAbsolutePath(), "libs-example-local", threads,
						new Build("my-build", buildNumber, URI.create("https://ci.example.com/builds/" + buildNumber)),
						(artifactProperties != null) ? List.of(artifactProperties) : Collections.emptyList()));
	}

}
