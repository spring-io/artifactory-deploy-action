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
import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import io.spring.artifactory.deploy.artifactory.payload.BuildInfo;
import io.spring.artifactory.deploy.artifactory.payload.Checksums;
import io.spring.artifactory.deploy.artifactory.payload.CreatedReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.DeployableArtifact;
import io.spring.artifactory.deploy.artifactory.payload.PromotedReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.Promotion;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundlePromotion;
import io.spring.artifactory.deploy.system.Logger;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriBuilder;

/**
 * Default {@link Artifactory} implementation communicating over HTTP.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Gabriel Petrovay
 */
public class HttpArtifactory implements Artifactory {

	private static final long CHECKSUM_THRESHOLD = 10 * 1024;

	private final Logger logger;

	private final RestClient restClient;

	private final Duration retryDelay;

	/**
	 * Creates a new {@link HttpArtifactory} with a default delay.
	 * @param logger the logger
	 * @param restClientBuilder builder for creating the {@link RestClient}
	 * @param uri the Artifactory server URI
	 * @param username the username for authentication
	 * @param password the password for authentication
	 */
	public HttpArtifactory(Logger logger, RestClient.Builder restClientBuilder, URI uri, String username,
			String password) {
		this(logger, restClientBuilder, uri, username, password, Duration.ofSeconds(5));
	}

	/**
	 * Creates a new {@link HttpArtifactory}.
	 * @param logger the logger
	 * @param restClientBuilder builder for creating the {@link RestClient}
	 * @param uri the Artifactory server URI
	 * @param username the username for authentication
	 * @param password the password for authentication
	 * @param retryDelay delay between retries on transient failures
	 */
	public HttpArtifactory(Logger logger, RestClient.Builder restClientBuilder, URI uri, String username,
			String password, Duration retryDelay) {
		this.logger = logger;
		restClientBuilder = restClientBuilder.clone().configureMessageConverters((converters) -> {
			converters.registerDefaults();
			converters.withJsonConverter(new JacksonJsonHttpMessageConverter(JsonMapper.builder()
				.changeDefaultPropertyInclusion((inclusion) -> inclusion.withValueInclusion(Include.NON_EMPTY))));
		});
		if (StringUtils.hasText(username)) {
			restClientBuilder = restClientBuilder.defaultHeaders((headers) -> headers.setBasicAuth(username, password));
		}
		this.restClient = restClientBuilder.baseUrl(uri).build();
		this.retryDelay = retryDelay;
	}

	@Override
	public void deploy(String repository, DeployableArtifact artifact) {
		try {
			Assert.notNull(artifact, "'artifact' must not be null");
			if (artifact.getSize() <= CHECKSUM_THRESHOLD) {
				deployUsingContent(repository, artifact);
				return;
			}
			try {
				deployUsingChecksum(repository, artifact);
			}
			catch (Exception ex) {
				if (!(ex instanceof HttpClientErrorException || isCausedByIOException(ex))) {
					throw ex;
				}
				deployUsingContent(repository, artifact);
			}
		}
		catch (Exception ex) {
			throw new RuntimeException(
					"Error deploying artifact " + artifact.getPath() + " with checksums " + artifact.getChecksums(),
					ex);
		}
	}

	private void deployUsingChecksum(String repository, DeployableArtifact artifact) {
		this.restClient.put()
			.uri((builder) -> deployUri(builder, repository, artifact))
			.contentType(MediaType.APPLICATION_OCTET_STREAM)
			.headers((headers) -> headers(headers, artifact))
			.header("X-Checksum-Deploy", "true")
			.retrieve()
			.toBodilessEntity();
	}

	private void deployUsingContent(String repository, DeployableArtifact artifact) {
		int attempt = 0;
		while (true) {
			try {
				attempt++;
				this.restClient.put()
					.uri((builder) -> deployUri(builder, repository, artifact))
					.contentType(MediaType.APPLICATION_OCTET_STREAM)
					.headers((headers) -> headers(headers, artifact))
					.contentLength(artifact.getSize())
					.body(artifact.getContent())
					.retrieve()
					.toBodilessEntity();
				return;
			}
			catch (RestClientResponseException | ResourceAccessException ex) {
				HttpStatusCode statusCode = (ex instanceof RestClientResponseException restClientException)
						? restClientException.getStatusCode() : null;
				boolean flaky = (statusCode == HttpStatus.BAD_REQUEST || statusCode == HttpStatus.NOT_FOUND)
						|| isCausedByIOException(ex);
				if (!flaky || attempt >= 3) {
					throw ex;
				}
				this.logger.log("Deploy failed with {} response. Retrying in {}ms.", statusCode,
						this.retryDelay.toMillis());
				trySleep(this.retryDelay);
			}
		}
	}

	private boolean isCausedByIOException(Throwable ex) {
		while (ex != null) {
			if (ex instanceof IOException) {
				return true;
			}
			ex = ex.getCause();
		}
		return false;
	}

	private void trySleep(Duration time) {
		try {
			Thread.sleep(time.toMillis());
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	private URI deployUri(UriBuilder builder, String repository, DeployableArtifact artifact) {
		return builder.pathSegment(repository)
			.path(artifact.getPath())
			.path(buildMatrixParams(artifact.getProperties()))
			.build();
	}

	private void headers(HttpHeaders headers, DeployableArtifact artifact) {
		Checksums checksums = artifact.getChecksums();
		headers.add("X-Checksum-Sha1", checksums.getSha1());
		headers.add("X-Checksum-Md5", checksums.getMd5());
	}

	private String buildMatrixParams(Map<String, String> matrixParams) {
		StringBuilder matrix = new StringBuilder();
		if (matrixParams != null && !matrixParams.isEmpty()) {
			for (Map.Entry<String, String> entry : matrixParams.entrySet()) {
				matrix.append(";" + entry.getKey() + "=" + entry.getValue());
			}
		}
		return matrix.toString();
	}

	@Override
	public void addBuildRun(String project, String buildName, BuildRun buildRun) {
		this.logger.debug("Adding {} build {}", buildName, buildRun.number());
		String buildUrl = (buildRun.uri() != null) ? buildRun.uri().toString() : null;
		BuildInfo buildInfo = new BuildInfo(buildName, buildRun.number(), buildRun.started(), buildUrl, buildRun.vcs(),
				buildRun.modules());
		this.restClient.put()
			.uri((builder) -> buildRunUri(builder, project))
			.contentType(MediaType.APPLICATION_JSON)
			.body(buildInfo)
			.retrieve()
			.toBodilessEntity();
	}

	private URI buildRunUri(UriBuilder builder, String project) {
		builder = builder.pathSegment("api", "build");
		if (StringUtils.hasText(project)) {
			this.logger.debug("Publishing to project {}", project);
			builder = builder.queryParam("project", project);
		}
		URI uri = builder.build();
		this.logger.debug("Publishing build info to {}", uri);
		return uri;
	}

	@Override
	public void promoteBuild(String buildName, String buildNumber, String project, Promotion promotion) {
		Assert.hasText(buildName, "'buildName' must not be empty");
		Assert.hasText(buildNumber, "'buildNumber' must not be empty");
		Assert.notNull(promotion, "'promotion' must not be null");
		this.restClient.post()
			.uri((builder) -> promoteBuildUri(builder, buildName, buildNumber, project))
			.contentType(MediaType.APPLICATION_JSON)
			.body(promotion)
			.retrieve()
			.toBodilessEntity();

	}

	private URI promoteBuildUri(UriBuilder builder, String buildName, String buildNumber, String project) {
		builder = builder.pathSegment("api", "build", "promote", buildName, buildNumber);
		if (StringUtils.hasText(project)) {
			builder = builder.queryParam("project", project);
		}
		return builder.build();
	}

	@Override
	public void deleteBuild(String buildName, BuildNumbers buildNumbers, String project, Delete... delete) {
		Assert.hasText(buildName, "'buildName' must not be empty");
		this.restClient.delete()
			.uri((builder) -> deleteBuildUri(builder, buildName, buildNumbers, project, Set.of(delete)))
			.retrieve()
			.toBodilessEntity();
	}

	private URI deleteBuildUri(UriBuilder builder, String buildName, BuildNumbers buildNumbers, String project,
			Set<Delete> delete) {
		builder = builder.pathSegment("api", "build", buildName);
		if (buildNumbers != null && !buildNumbers.value().isEmpty()) {
			builder = builder.queryParam("buildNumbers",
					StringUtils.collectionToCommaDelimitedString(buildNumbers.value()));
		}
		if (StringUtils.hasText(project)) {
			builder = builder.queryParam("project", project);
		}
		if (delete.contains(Delete.ARTIFACTS)) {
			builder = builder.queryParam("artifacts", "1");
		}
		if (delete.contains(Delete.ALL_BUILDS)) {
			builder = builder.queryParam("deleteAll", "1");
		}
		return builder.build();
	}

	@Override
	public CreatedReleaseBundle createReleaseBundle(boolean async, boolean failFast, String project,
			String repositoryKey, ReleaseBundle releaseBundle) {
		Assert.notNull(releaseBundle, "'releaseBundle' must not be null");
		return this.restClient.post()
			.uri((builder) -> createReleaseBundleUri(builder, async, failFast, project, repositoryKey))
			.contentType(MediaType.APPLICATION_JSON)
			.body(releaseBundle)
			.retrieve()
			.body(CreatedReleaseBundle.class);
	}

	private URI createReleaseBundleUri(UriBuilder builder, boolean async, boolean failFast, String project,
			String repositoryKey) {
		builder = builder.pathSegment("lifecycle", "api", "v2", "release_bundle");
		if (!async) {
			builder = builder.queryParam("async", false);
		}
		if (!failFast) {
			builder = builder.queryParam("fail_fast", false);
		}
		if (StringUtils.hasText(project)) {
			builder = builder.queryParam("project", project);
		}
		if (StringUtils.hasText(repositoryKey)) {
			builder = builder.queryParam("repository_key", project);
		}
		return builder.build();
	}

	@Override
	public void deleteReleaseBundle(String name, String version, String project, String repositoryKey, boolean async,
			boolean isRemoteDeleteByDistribution) {
		Assert.hasText(name, "'name' must not be empty");
		Assert.hasText(name, "'version' must not be empty");
		this.restClient.delete()
			.uri((builder) -> deleteReleaseBundleUri(builder, name, version, project, repositoryKey, async,
					isRemoteDeleteByDistribution))
			.retrieve()
			.toBodilessEntity();
	}

	private URI deleteReleaseBundleUri(UriBuilder builder, String name, String version, String project,
			String repositoryKey, boolean async, boolean isRemoteDeleteByDistribution) {
		builder = builder.pathSegment("lifecycle", "api", "v2", "release_bundle", "records", name, version);
		if (StringUtils.hasText(project)) {
			builder = builder.queryParam("project", project);
		}
		if (StringUtils.hasText(repositoryKey)) {
			builder = builder.queryParam("repository_key", repositoryKey);
		}
		if (!async) {
			builder = builder.queryParam("async", false);
		}
		if (isRemoteDeleteByDistribution) {
			builder = builder.queryParam("is_remote_delete_by_distribution", true);
		}
		return builder.build();
	}

	@Override
	public PromotedReleaseBundle promoteReleaseBundle(String name, String version, boolean async,
			PromoteReleaseBundleOperation operation, String project, String repositoryKey,
			ReleaseBundlePromotion releaseBundlePromotion) {
		Assert.hasText(name, "'name' must not be empty");
		Assert.hasText(name, "'version' must not be empty");
		return this.restClient.post()
			.uri((builder) -> promoteReleaseBundleUrl(builder, name, version, async, operation, project, repositoryKey))
			.body(releaseBundlePromotion)
			.retrieve()
			.body(PromotedReleaseBundle.class);
	}

	private URI promoteReleaseBundleUrl(UriBuilder builder, String name, String version, boolean async,
			PromoteReleaseBundleOperation operation, String project, String repositoryKey) {
		builder = builder.pathSegment("lifecycle", "api", "v2", "promotion", "records", name, version);
		if (!async) {
			builder = builder.queryParam("async", false);
		}
		if (operation != null && operation != PromoteReleaseBundleOperation.COPY) {
			builder = builder.queryParam("operation", operation.toString().toLowerCase(Locale.ROOT));
		}
		if (StringUtils.hasText(project)) {
			builder = builder.queryParam("project", project);
		}
		if (StringUtils.hasText(repositoryKey)) {
			builder = builder.queryParam("repository_key", repositoryKey);
		}
		return builder.build();
	}

}
