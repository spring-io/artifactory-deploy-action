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

package io.spring.github.actions.artifactorydeploy;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy.ArtifactProperties;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Signing;
import io.spring.github.actions.artifactorydeploy.artifactory.Artifactory;
import io.spring.github.actions.artifactorydeploy.artifactory.Artifactory.BuildRun;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildModule;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableFileArtifact;
import io.spring.github.actions.artifactorydeploy.io.DirectoryScanner;
import io.spring.github.actions.artifactorydeploy.io.FileSet;
import io.spring.github.actions.artifactorydeploy.io.FileSet.Category;
import io.spring.github.actions.artifactorydeploy.io.PathFilter;
import io.spring.github.actions.artifactorydeploy.maven.MavenBuildModulesGenerator;
import io.spring.github.actions.artifactorydeploy.maven.MavenCoordinates;
import io.spring.github.actions.artifactorydeploy.maven.MavenVersionType;
import io.spring.github.actions.artifactorydeploy.openpgp.ArmoredAsciiSigner;
import io.spring.github.actions.artifactorydeploy.system.ConsoleLogger;

import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

/**
 * Deployer for deploying to Artifactory.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Gabriel Petrovay
 * @author Andy Wilkinson
 */
@Component
public class Deployer {

	private static final Set<String> METADATA_FILES = Collections
		.unmodifiableSet(new HashSet<>(Arrays.asList("maven-metadata.xml", "maven-metadata-local.xml")));

	private static final Set<String> CHECKSUM_FILE_EXTENSIONS = Collections
		.unmodifiableSet(new HashSet<>(Arrays.asList(".md5", ".sha1", ".sha256", ".sha512")));

	private static final ConsoleLogger console = new ConsoleLogger();

	private final ArtifactoryDeployProperties artifactoryProperties;

	private final Artifactory artifactory;

	private final DirectoryScanner directoryScanner;

	public Deployer(ArtifactoryDeployProperties properties, Artifactory artifactory,
			DirectoryScanner directoryScanner) {
		this.artifactoryProperties = properties;
		this.artifactory = artifactory;
		this.directoryScanner = directoryScanner;
	}

	public void deploy() {
		Instant started = Instant.now();
		Map<String, String> buildProperties = getBuildProperties(this.artifactoryProperties.deploy().build().number(),
				started);
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = getBatchedArtifacts(buildProperties);
		batchedArtifacts = signArtifactsIfNecessary(batchedArtifacts, buildProperties);
		int size = batchedArtifacts.values().stream().mapToInt(List::size).sum();
		Assert.state(size > 0, "No artifacts found to deploy");
		console.log("Deploying {} artifacts to {} in {} as build {} of {} using {} thread(s)", size,
				this.artifactoryProperties.deploy().repository(), this.artifactoryProperties.server().uri(),
				this.artifactoryProperties.deploy().build().number(),
				this.artifactoryProperties.deploy().build().name(), this.artifactoryProperties.deploy().threads());
		deployArtifacts(batchedArtifacts);
		addBuildRun(this.artifactoryProperties.deploy().build().number(), started, batchedArtifacts);
		console.debug("Done");
	}

	private MultiValueMap<Category, DeployableArtifact> getBatchedArtifacts(Map<String, String> buildProperties) {
		File root = new File(this.artifactoryProperties.deploy().folder());
		Assert.state(!ObjectUtils.isEmpty(root.listFiles()),
				() -> "No artifacts found in empty directory '%s'".formatted(root.getAbsolutePath()));
		console.debug("Getting deployable artifacts from {}", root);
		FileSet fileSet = this.directoryScanner.scan(root).filter(getChecksumFilter()).filter(getMetadataFilter());
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = new LinkedMultiValueMap<>();
		Set<String> paths = new HashSet<>();
		fileSet.batchedByCategory().forEach((category, files) -> {
			files.forEach((file) -> {
				String path = DeployableFileArtifact.calculatePath(root, file);
				console.debug("Including file {} with path {}", file, path);
				Map<String, String> properties = new LinkedHashMap<>(buildProperties);
				properties.putAll(getArtifactProperties(path));
				path = stripSnapshotTimestamp(path);
				if (paths.add(path)) {
					batchedArtifacts.add(category, new DeployableFileArtifact(path, file, properties, null));
				}
			});
		});
		return batchedArtifacts;
	}

	private String stripSnapshotTimestamp(String path) {
		MavenCoordinates coordinates = MavenCoordinates.fromPath(path);
		if (coordinates.getVersionType() != MavenVersionType.TIMESTAMP_SNAPSHOT) {
			return path;
		}
		String stripped = path.replace(coordinates.getSnapshotVersion(), coordinates.getVersion());
		console.debug("Stripped timestamp version {} to {}", path, stripped);
		return stripped;
	}

	private Map<String, String> getArtifactProperties(String path) {
		Map<String, String> properties = new LinkedHashMap<>();
		for (ArtifactProperties artifactProperties : this.artifactoryProperties.deploy().artifactProperties()) {
			if (getFilter(artifactProperties).isMatch(path)) {
				console.debug("Artifact properties matched, adding properties {}", artifactProperties.properties());
				properties.putAll(artifactProperties.properties());
			}
		}
		return properties;
	}

	private PathFilter getFilter(ArtifactProperties artifactProperties) {
		console.debug("Creating artifact properties filter including {} and excluding {}", artifactProperties.include(),
				artifactProperties.exclude());
		return new PathFilter(artifactProperties.include(), artifactProperties.exclude());
	}

	private Map<String, String> getBuildProperties(int buildNumber, Instant started) {
		return Map.of("build.name", this.artifactoryProperties.deploy().build().name(), "build.number",
				Integer.toString(buildNumber), "build.timestamp", Long.toString(started.toEpochMilli()));
	}

	private MultiValueMap<Category, DeployableArtifact> signArtifactsIfNecessary(
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts, Map<String, String> buildProperties) {
		Signing signing = this.artifactoryProperties.signing();
		if (signing == null || !StringUtils.hasText(signing.key())) {
			return batchedArtifacts;
		}
		return signArtifacts(batchedArtifacts, signing.key(), signing.passphrase(), buildProperties);
	}

	private MultiValueMap<Category, DeployableArtifact> signArtifacts(
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts, String signingKey, String signingPassphrase,
			Map<String, String> buildProperties) {
		try {
			console.log("Signing artifacts");
			ArmoredAsciiSigner signer = ArmoredAsciiSigner.get(signingKey, signingPassphrase);
			return new DeployableArtifactsSigner(signer, buildProperties).addSignatures(batchedArtifacts);
		}
		catch (IOException ex) {
			throw new IllegalStateException("Unable to sign artifacts", ex);
		}
	}

	private void deployArtifacts(MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		ExecutorService executor = Executors.newFixedThreadPool(this.artifactoryProperties.deploy().threads());
		Function<DeployableArtifact, CompletableFuture<?>> deployer = (deployableArtifact) -> getArtifactDeployer(
				deployableArtifact);
		try {
			batchedArtifacts.forEach((category, artifacts) -> deploy(category, artifacts, deployer));
		}
		finally {
			executor.shutdown();
		}
	}

	private void deploy(Category category, List<DeployableArtifact> artifacts,
			Function<DeployableArtifact, CompletableFuture<?>> deployer) {
		console.debug("Deploying {} artifacts", category);
		deploy(artifacts.stream().map(deployer).toArray(CompletableFuture[]::new));
	}

	private void deploy(CompletableFuture<?>[] batch) {
		try {
			CompletableFuture.allOf(batch).get();
		}
		catch (ExecutionException ex) {
			throw new RuntimeException(ex);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	private CompletableFuture<?> getArtifactDeployer(DeployableArtifact deployableArtifact) {
		return CompletableFuture.runAsync(() -> deployArtifact(deployableArtifact));
	}

	private void deployArtifact(DeployableArtifact deployableArtifact) {
		console.log("Deploying {} {} ({}/{})", deployableArtifact.getPath(), deployableArtifact.getProperties(),
				deployableArtifact.getChecksums().getSha1(), deployableArtifact.getChecksums().getMd5());
		this.artifactory.deploy(this.artifactoryProperties.deploy().repository(), deployableArtifact);
	}

	private Predicate<File> getMetadataFilter() {
		return (file) -> !METADATA_FILES.contains(file.getName().toLowerCase());
	}

	private Predicate<File> getChecksumFilter() {
		return (file) -> {
			String name = file.getName().toLowerCase();
			for (String extension : CHECKSUM_FILE_EXTENSIONS) {
				if (name.endsWith(extension)) {
					return false;
				}
			}
			return true;
		};
	}

	private void addBuildRun(int buildNumber, Instant started,
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		List<DeployableArtifact> artifacts = batchedArtifacts.values()
			.stream()
			.flatMap(List::stream)
			.collect(Collectors.toList());
		console.debug("Adding build run {}", buildNumber);
		List<BuildModule> modules = new MavenBuildModulesGenerator().getBuildModules(artifacts);
		this.artifactory.addBuildRun(this.artifactoryProperties.deploy().project(),
				this.artifactoryProperties.deploy().build().name(),
				new BuildRun(buildNumber, started, this.artifactoryProperties.deploy().build().uri(), modules));
	}

}
