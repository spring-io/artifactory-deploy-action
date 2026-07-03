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

package io.spring.artifactory.deploy;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.spring.artifactory.deploy.Deployer.ArtifactProperties;
import io.spring.artifactory.deploy.artifactory.Artifactory;
import io.spring.artifactory.deploy.artifactory.Artifactory.BuildRun;
import io.spring.artifactory.deploy.artifactory.payload.BuildModule;
import io.spring.artifactory.deploy.artifactory.payload.DeployableArtifact;
import io.spring.artifactory.deploy.io.DirectoryScanner;
import io.spring.artifactory.deploy.io.FileSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

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

	private static final String REPOSITORY = "libs-example-local";

	private static final String BUILD_NAME = "my-build";

	private static final String PROJECT = null;

	private static final String REVISION = "b8993e365706816aba4f25717851a18c9cd0d873";

	@TempDir
	Path tempDir;

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
		assertThatIllegalStateException()
			.isThrownBy(() -> createDeployer().deploy(REPOSITORY, "1", BUILD_NAME, createBuildUri(1), PROJECT, REVISION,
					this.tempDir, null, null))
			.withMessage("No artifacts found in empty directory '%s'".formatted(this.tempDir));
	}

	@Test
	void deployWhenScanningFindsNoFilesThrowsException() throws IOException {
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of());
		Files.createFile(this.tempDir.resolve("file"));
		assertThatIllegalStateException()
			.isThrownBy(() -> createDeployer().deploy(REPOSITORY, "1", BUILD_NAME, createBuildUri(1), PROJECT, REVISION,
					this.tempDir, null, null))
			.withMessage("No artifacts found to deploy");
	}

	@Test
	void deployAddsBuildRun() throws Exception {
		Path artifact = this.tempDir.resolve("com/example/foo/0.0.1/foo-0.0.1.jar");
		Files.createDirectories(artifact.getParent());
		Files.createFile(artifact);
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact.toFile()));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		BuildRun buildRun = this.buildRunCaptor.getValue();
		assertThat(buildRun.number()).isEqualTo("1234");
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
		Path artifact = this.tempDir.resolve("com/example/foo/0.0.1/foo-0.0.1.jar");
		Files.createDirectories(artifact.getParent());
		Files.createFile(artifact);
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact.toFile()));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), "my-project", REVISION,
				this.tempDir, null, null);
		verify(this.artifactory).addBuildRun(eq("my-project"), eq("my-build"), this.buildRunCaptor.capture());
		BuildRun buildRun = this.buildRunCaptor.getValue();
		assertThat(buildRun.number()).isEqualTo("1234");
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
		Path artifact = this.tempDir.resolve("com/example/foo/0.0.1/foo-0.0.1.jar");
		Files.createDirectories(artifact.getParent());
		Files.createFile(artifact);
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact.toFile()));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
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
		createDeployer(2).deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
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
		Path artifact = this.tempDir.resolve("com/example/foo/0.0.1/foo-0.0.1.jar");
		Files.createDirectories(artifact.getParent());
		Files.createFile(artifact);
		given(this.directoryScanner.scan(any(File.class))).willReturn(FileSet.of(artifact.toFile()));
		ArtifactProperties artifactProperties = new ArtifactProperties(List.of("/**/foo-0.0.1.jar"),
				Collections.emptyList(), Map.of("foo", "bar"));
		createDeployer(2).deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				List.of(artifactProperties), null);
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
		Path fooModule = this.tempDir.resolve("com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.toFile(), "foo-0.0.1.jar"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.md5"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.sha1"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.sha256"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.sha512"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir.toFile())).willReturn(FileSet.of(files));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployFiltersOutMavenMetadataFiles() throws IOException {
		Path fooModule = this.tempDir.resolve("com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.getParent().toFile(), "maven-metadata.xml"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir.toFile())).willReturn(FileSet.of(files));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployFiltersOutMavenMetadataLocalFiles() throws IOException {
		Path fooModule = this.tempDir.resolve("com/example/foo/0.0.1");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.getParent().toFile(), "maven-metadata-local.xml"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir.toFile())).willReturn(FileSet.of(files));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
		verify(this.artifactory).addBuildRun(eq(null), eq("my-build"), this.buildRunCaptor.capture());
		List<BuildModule> buildModules = this.buildRunCaptor.getValue().modules();
		assertThat(buildModules).hasSize(1).first().satisfies((module) -> assertThat(module.artifacts()).hasSize(1));
	}

	@Test
	void deployWithSnapshotTimestampArtifactChangesArtifactPath() throws IOException {
		Path fooModule = this.tempDir.resolve("com/example/foo/0.0.1-SNAPSHOT");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.toFile(), "foo-0.0.1-20240305.110926-1.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir.toFile())).willReturn(FileSet.of(files));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
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
		Path fooModule = this.tempDir.resolve("com/example/foo/0.0.1-SNAPSHOT");
		createStructure(fooModule);
		List<File> files = new ArrayList<>();
		files.add(new File(fooModule.toFile(), "foo-0.0.1-20240305.110926-1.jar"));
		files.add(new File(fooModule.toFile(), "foo-0.0.1-20240305.110926-2.jar"));
		createEmptyFiles(files);
		given(this.directoryScanner.scan(this.tempDir.toFile())).willReturn(FileSet.of(files));
		createDeployer().deploy(REPOSITORY, "1234", BUILD_NAME, createBuildUri(1234), PROJECT, REVISION, this.tempDir,
				null, null);
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

	private File createStructure(Path directory, String... paths) throws IOException {
		Path dir = directory.resolve(String.join("/", paths));
		Files.createDirectories(dir);
		return dir.toFile();
	}

	private void createEmptyFiles(List<File> files) throws IOException {
		for (File file : files) {
			Files.createFile(file.toPath());
		}
	}

	private Deployer createDeployer() {
		return createDeployer(1);
	}

	private Deployer createDeployer(int threads) {
		return new Deployer(this.artifactory, this.directoryScanner, URI.create("https://repo.example.com"), threads);
	}

	private URI createBuildUri(int buildNumber) {
		return URI.create("https://ci.example.com/builds/" + buildNumber);
	}

}
