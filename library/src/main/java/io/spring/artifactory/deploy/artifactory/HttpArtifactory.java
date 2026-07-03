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
import java.util.Map;

import io.spring.artifactory.deploy.artifactory.payload.BuildInfo;
import io.spring.artifactory.deploy.artifactory.payload.Checksums;
import io.spring.artifactory.deploy.artifactory.payload.DeployableArtifact;
import io.spring.artifactory.deploy.system.Logger;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
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
		if (StringUtils.hasText(username)) {
			restClientBuilder = restClientBuilder.defaultHeaders((headers) -> headers.setBasicAuth(username, password));
		}
		this.restClient = restClientBuilder.baseUrl(uri).build();
		this.retryDelay = retryDelay;
	}

	@Override
	public void deploy(String repository, DeployableArtifact artifact) {
		try {
			Assert.notNull(artifact, "Artifact must not be null");
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

}
