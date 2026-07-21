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
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import io.spring.artifactory.deploy.artifactory.Artifactory;
import io.spring.artifactory.deploy.artifactory.Artifactory.BuildRun;
import io.spring.artifactory.deploy.artifactory.payload.BuildModule;
import io.spring.artifactory.deploy.artifactory.payload.DeployableArtifact;
import io.spring.artifactory.deploy.artifactory.payload.DeployableFileArtifact;
import io.spring.artifactory.deploy.artifactory.payload.Vcs;
import io.spring.artifactory.deploy.io.DirectoryScanner;
import io.spring.artifactory.deploy.io.FileSet;
import io.spring.artifactory.deploy.io.FileSet.Category;
import io.spring.artifactory.deploy.io.PathFilter;
import io.spring.artifactory.deploy.maven.MavenBuildModulesGenerator;
import io.spring.artifactory.deploy.maven.MavenCoordinates;
import io.spring.artifactory.deploy.maven.MavenVersionType;
import io.spring.artifactory.deploy.openpgp.ArmoredAsciiSigner;
import io.spring.artifactory.deploy.system.Logger;

import org.springframework.scheduling.concurrent.CustomizableThreadFactory;
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
public class Deployer {

	private static final Set<String> METADATA_FILES = Set.of("maven-metadata.xml", "maven-metadata-local.xml");

	private static final Set<String> CHECKSUM_FILE_EXTENSIONS = Set.of(".md5", ".sha1", ".sha256", ".sha512");

	private final Logger logger;

	private final Artifactory artifactory;

	private final DirectoryScanner directoryScanner;

	private final URI server;

	private final int threads;

	/**
	 * Creates a new {@link Deployer}.
	 * @param logger the logger
	 * @param artifactory the Artifactory instance to deploy to
	 * @param directoryScanner the scanner used to find files to deploy
	 * @param server uri of the Artifactory server
	 * @param threads number of threads to use for parallel deployment
	 */
	public Deployer(Logger logger, Artifactory artifactory, DirectoryScanner directoryScanner, URI server,
			int threads) {
		this.logger = logger;
		this.artifactory = artifactory;
		this.directoryScanner = directoryScanner;
		this.server = server;
		this.threads = threads;
	}

	/**
	 * Deploys artifacts from the given folder to Artifactory.
	 * @param repository the target repository
	 * @param buildNumber the build number
	 * @param buildName the build name
	 * @param buildUri uri of the build on the CI server, or {@code null}
	 * @param project the Artifactory project key, or {@code null}
	 * @param revision the VCS revision, or {@code null}
	 * @param folder the folder containing artifacts to deploy
	 * @param artifactProperties per-path artifact property rules, or {@code null}
	 * @param signing signing configuration, or {@code null}
	 */
	public void deploy(String repository, String buildNumber, String buildName, URI buildUri, String project,
			String revision, Path folder, List<ArtifactProperties> artifactProperties, Signing signing) {
		deploy(repository, buildNumber, buildName, buildUri, project, revision, Instant.now(), folder,
				artifactProperties, signing);
	}

	/**
	 * Deploys artifacts from the given folder to Artifactory.
	 * @param repository the target repository
	 * @param buildNumber the build number
	 * @param buildName the build name
	 * @param buildUri uri of the build on the CI server, or {@code null}
	 * @param project the Artifactory project key, or {@code null}
	 * @param revision the VCS revision, or {@code null}
	 * @param started the timestamp of the build or {@code null}
	 * @param folder the folder containing artifacts to deploy
	 * @param artifactProperties per-path artifact property rules, or {@code null}
	 * @param signing signing configuration, or {@code null}
	 */
	public void deploy(String repository, String buildNumber, String buildName, URI buildUri, String project,
			String revision, Instant started, Path folder, List<ArtifactProperties> artifactProperties,
			Signing signing) {
		Map<String, String> buildProperties = getBuildProperties(buildNumber, buildName, started);
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = getBatchedArtifacts(buildProperties, folder,
				artifactProperties);
		batchedArtifacts = signArtifactsIfNecessary(batchedArtifacts, buildProperties, signing);
		int size = batchedArtifacts.values().stream().mapToInt(List::size).sum();
		Assert.state(size > 0, "No artifacts found to deploy");
		ProgressTracker progressTracker = new ProgressTracker(this.logger, size);
		this.logger.log("Deploying {} artifacts to {} in {} as build {} of {} using {} thread(s)", size, repository,
				this.server, buildNumber, buildName, this.threads);
		deployArtifacts(batchedArtifacts, repository, progressTracker);
		addBuildRun(buildNumber, buildName, buildUri, project, revision, started, batchedArtifacts);
		this.logger.debug("Done");
	}

	private MultiValueMap<Category, DeployableArtifact> getBatchedArtifacts(Map<String, String> buildProperties,
			Path folder, List<ArtifactProperties> artifactProperties) {
		File root = folder.toFile();
		Assert.state(!ObjectUtils.isEmpty(root.listFiles()),
				() -> "No artifacts found in empty directory '%s'".formatted(root.getAbsolutePath()));
		this.logger.debug("Getting deployable artifacts from {}", root);
		FileSet fileSet = this.directoryScanner.scan(root).filter(getChecksumFilter()).filter(getMetadataFilter());
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = new LinkedMultiValueMap<>();
		Set<String> paths = new HashSet<>();
		fileSet.batchedByCategory().forEach((category, files) -> {
			files.forEach((file) -> {
				String path = DeployableFileArtifact.calculatePath(root, file);
				this.logger.debug("Including file {} with path {}", file, path);
				Map<String, String> properties = new LinkedHashMap<>(buildProperties);
				properties.putAll(getArtifactProperties(path, artifactProperties));
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
		this.logger.debug("Stripped timestamp version {} to {}", path, stripped);
		return stripped;
	}

	private Map<String, String> getArtifactProperties(String path, List<ArtifactProperties> artifactProperties) {
		if (artifactProperties == null) {
			return Collections.emptyMap();
		}
		Map<String, String> properties = new LinkedHashMap<>();
		for (ArtifactProperties artifactProperty : artifactProperties) {
			if (getFilter(artifactProperty).isMatch(path)) {
				this.logger.debug("Artifact properties matched, adding properties {}", artifactProperty.properties());
				properties.putAll(artifactProperty.properties());
			}
		}
		return properties;
	}

	private PathFilter getFilter(ArtifactProperties artifactProperties) {
		this.logger.debug("Creating artifact properties filter including {} and excluding {}",
				artifactProperties.include(), artifactProperties.exclude());
		return new PathFilter(artifactProperties.include(), artifactProperties.exclude());
	}

	private Map<String, String> getBuildProperties(String buildNumber, String buildName, Instant started) {
		Map<String, String> buildProperties = new LinkedHashMap<>();
		buildProperties.put("build.name", buildName);
		buildProperties.put("build.number", buildNumber);
		if (started != null) {
			buildProperties.put("build.timestamp", Long.toString(started.toEpochMilli()));
		}
		return Collections.unmodifiableMap(buildProperties);
	}

	private MultiValueMap<Category, DeployableArtifact> signArtifactsIfNecessary(
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts, Map<String, String> buildProperties,
			Signing signing) {
		if (signing == null || !StringUtils.hasText(signing.key())) {
			return batchedArtifacts;
		}
		return signArtifacts(batchedArtifacts, signing.key(), signing.passphrase(), signing.keyId(), buildProperties);
	}

	private MultiValueMap<Category, DeployableArtifact> signArtifacts(
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts, String signingKey, String signingPassphrase,
			String signingKeyId, Map<String, String> buildProperties) {
		try {
			this.logger.log("Signing artifacts");
			ArmoredAsciiSigner signer = ArmoredAsciiSigner.get(signingKey, signingPassphrase, signingKeyId);
			return new DeployableArtifactsSigner(this.logger, signer, buildProperties).addSignatures(batchedArtifacts);
		}
		catch (IOException ex) {
			throw new IllegalStateException("Unable to sign artifacts", ex);
		}
	}

	private void deployArtifacts(MultiValueMap<Category, DeployableArtifact> batchedArtifacts, String repository,
			ProgressTracker progressTracker) {
		ExecutorService executor = Executors.newFixedThreadPool(this.threads,
				new CustomizableThreadFactory("deployer-"));
		Function<DeployableArtifact, CompletableFuture<?>> deployer = (deployableArtifact) -> getArtifactDeployer(
				deployableArtifact, progressTracker, executor, repository);
		try {
			batchedArtifacts.forEach((category, artifacts) -> deploy(category, artifacts, deployer));
		}
		finally {
			executor.shutdown();
		}
	}

	private void deploy(Category category, List<DeployableArtifact> artifacts,
			Function<DeployableArtifact, CompletableFuture<?>> deployer) {
		this.logger.debug("Deploying {} artifacts", category);
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

	private CompletableFuture<?> getArtifactDeployer(DeployableArtifact deployableArtifact,
			ProgressTracker progressTracker, Executor executor, String repository) {
		return CompletableFuture.runAsync(() -> deployArtifact(deployableArtifact, repository, progressTracker),
				executor);
	}

	private void deployArtifact(DeployableArtifact deployableArtifact, String repository,
			ProgressTracker progressTracker) {
		this.logger.debug("Deploying {} {} ({}/{})", deployableArtifact.getPath(), deployableArtifact.getProperties(),
				deployableArtifact.getChecksums().getSha1(), deployableArtifact.getChecksums().getMd5());
		this.artifactory.deploy(repository, deployableArtifact);
		progressTracker.artifactDeployed();
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

	private void addBuildRun(String buildNumber, String buildName, URI buildUri, String project, String revision,
			Instant started, MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		this.logger.debug("Adding build run {}", buildNumber);
		this.artifactory.addBuildRun(project, buildName,
				createBuildRun(buildNumber, buildUri, revision, started, batchedArtifacts));
	}

	private BuildRun createBuildRun(String buildNumber, URI buildUri, String revision, Instant started,
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		Vcs vcs = createVcs(revision);
		List<BuildModule> modules = asBuildModules(batchedArtifacts);
		return new BuildRun(buildNumber, started, buildUri, vcs, modules);
	}

	private Vcs createVcs(String revision) {
		return StringUtils.hasText(revision) ? new Vcs(revision) : null;
	}

	private List<BuildModule> asBuildModules(MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		List<DeployableArtifact> artifacts = batchedArtifacts.values()
			.stream()
			.flatMap(List::stream)
			.collect(Collectors.toList());
		return new MavenBuildModulesGenerator().getBuildModules(artifacts);
	}

	/**
	 * Properties to attach to artifacts matching include/exclude path patterns.
	 *
	 * @param include Ant-style path patterns for artifacts to include
	 * @param exclude Ant-style path patterns for artifacts to exclude
	 * @param properties properties to attach to matching artifacts
	 */
	public record ArtifactProperties(List<String> include, List<String> exclude, Map<String, String> properties) {

		/**
		 * Creates a new {@link ArtifactProperties}, defaulting {@code null} lists/maps to
		 * empty.
		 * @param include ant-style path patterns for artifacts to include
		 * @param exclude ant-style path patterns for artifacts to exclude
		 * @param properties properties to attach to matching artifacts
		 */
		public ArtifactProperties(List<String> include, List<String> exclude, Map<String, String> properties) {
			this.include = (include != null) ? include : Collections.emptyList();
			this.exclude = (exclude != null) ? exclude : Collections.emptyList();
			this.properties = (properties != null) ? properties : Collections.emptyMap();
		}

	}

	/**
	 * GPG signing configuration.
	 *
	 * @param key the ASCII-armored GPG private key
	 * @param passphrase the passphrase protecting the key
	 * @param keyId optional key ID to select a subkey
	 */
	public record Signing(String key, String passphrase, String keyId) {
	}

	private static final class ProgressTracker {

		private static final int PROGRESS_INTERVAL = 50;

		private final AtomicInteger progress = new AtomicInteger();

		private final Logger logger;

		private volatile long start;

		private final int total;

		private ProgressTracker(Logger logger, int total) {
			this.logger = logger;
			this.total = total;
			this.start = System.currentTimeMillis();
		}

		private void artifactDeployed() {
			int current = this.progress.incrementAndGet();
			long elapsed = Duration.ofMillis(System.currentTimeMillis() - this.start).getSeconds();
			if (current == this.total) {
				this.logger.log("Deployed all {} artifacts in {}s", this.total, elapsed);
			}
			else if (current % PROGRESS_INTERVAL == 0) {
				this.logger.log("Deployed {} of {} artifacts in {}s", current, this.total, elapsed);
			}
		}

	}

}
