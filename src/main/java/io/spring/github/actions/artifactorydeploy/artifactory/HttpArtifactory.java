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

package io.spring.github.actions.artifactorydeploy.artifactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildInfo;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.Checksums;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.system.ConsoleLogger;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.RequestEntity.BodyBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Default {@link Artifactory} implementation communicating over HTTP.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Gabriel Petrovay
 */
class HttpArtifactory implements Artifactory {

	private static final long CHECKSUM_THRESHOLD = 10 * 1024;

	private static final ConsoleLogger console = new ConsoleLogger();

	private final RestTemplate restTemplate;

	private final String uri;

	private final Duration retryDelay;

	HttpArtifactory(RestTemplateBuilder restTemplateBuilder, URI uri, String username, String password) {
		this(restTemplateBuilder, uri, username, password, Duration.ofSeconds(5));
	}

	HttpArtifactory(RestTemplateBuilder restTemplateBuilder, URI uri, String username, String password,
			Duration retryDelay) {
		RestTemplateBuilder builder = restTemplateBuilder.connectTimeout(Duration.ofMinutes(1))
			.readTimeout(Duration.ofMinutes(5));
		if (StringUtils.hasText(username)) {
			builder = builder.basicAuthentication(username, password);
		}
		this.restTemplate = builder.build();
		String uriString = uri.toString();
		this.uri = uriString.endsWith("/") ? uriString : uriString + "/";
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
		RequestEntity<Void> request = deployRequest(repository, artifact).header("X-Checksum-Deploy", "true").build();
		this.restTemplate.exchange(request, Void.class);
	}

	private void deployUsingContent(String repository, DeployableArtifact artifact) {
		int attempt = 0;
		while (true) {
			try {
				attempt++;
				RequestEntity<Resource> request = deployRequest(repository, artifact).contentLength(artifact.getSize())
					.body(artifact.getContent());
				this.restTemplate.exchange(request, Void.class);
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
				console.log("Deploy failed with {} response. Retrying in {}ms.", statusCode,
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

	private BodyBuilder deployRequest(String repository, DeployableArtifact artifact) {
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(this.uri)
			.path(repository)
			.path(artifact.getPath())
			.path(buildMatrixParams(artifact.getProperties()))
			.build();
		URI uri = uriComponents.encode().toUri();
		Checksums checksums = artifact.getChecksums();
		return RequestEntity.put(uri)
			.contentType(MediaType.APPLICATION_OCTET_STREAM)
			.header("X-Checksum-Sha1", checksums.getSha1())
			.header("X-Checksum-Md5", checksums.getMd5());
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
		console.debug("Adding {} build {}", buildName, buildRun.number());
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(this.uri).path("api/build");
		if (StringUtils.hasText(project)) {
			console.debug("Publishing to project {}", project);
			builder = builder.queryParam("project", project);
		}
		UriComponents uriComponents = builder.build();
		URI uri = uriComponents.encode().toUri();
		console.debug("Publishing build info to {}", uri);
		RequestEntity<BuildInfo> request = RequestEntity.put(uri)
			.contentType(MediaType.APPLICATION_JSON)
			.body(new BuildInfo(buildName, Integer.toString(buildRun.number()), buildRun.started(),
					(buildRun.uri() != null) ? buildRun.uri().toString() : null, buildRun.vcs(), buildRun.modules()));
		ResponseEntity<Void> exchange = this.restTemplate.exchange(request, Void.class);
		exchange.getBody();
	}

}
