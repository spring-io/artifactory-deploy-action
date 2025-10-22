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

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import io.spring.github.actions.artifactorydeploy.artifactory.Artifactory.BuildRun;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildModule;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableFileArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.Vcs;
import org.json.JSONException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.boot.test.web.client.MockServerRestTemplateCustomizer;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.util.FileCopyUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link HttpArtifactory}.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 */
class HttpArtifactoryTests {

	private final MockServerRestTemplateCustomizer customizer = new MockServerRestTemplateCustomizer();

	private MockRestServiceServer server;

	private static final byte[] BYTES;

	private Artifactory artifactory;

	static {
		BYTES = new byte[1024 * 11];
		new Random().nextBytes(BYTES);
	}

	@TempDir
	File tempDir;

	@BeforeEach
	void setup() {
		RestTemplateBuilder builder = new RestTemplateBuilder().additionalCustomizers(this.customizer);
		this.artifactory = new HttpArtifactory(builder, URI.create("https://repo.example.com"), "alice", "secret",
				Duration.ofMillis(10));
		this.server = this.customizer.getServer();
	}

	@AfterEach
	void tearDown() {
		this.customizer.getExpectationManagers().clear();
	}

	@Test
	void deployUploadsTheDeployableArtifact() {
		DeployableArtifact artifact = artifact("/foo/bar.jar");
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar";
		this.server.expect(requestTo(url))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(header("X-Checksum-Deploy", "true"))
			.andExpect(header("X-Checksum-Sha1", artifact.getChecksums().getSha1()))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));
		this.server.expect(requestTo(url))
			.andExpect(header("Content-Length", Long.toString(artifact.getSize())))
			.andRespond(withSuccess());
		this.artifactory.deploy("libs-snapshot-local", artifact);
		this.server.verify();
	}

	@Test
	void deployUploadsTheDeployableArtifactWithMatrixParameters() {
		Map<String, String> properties = new HashMap<>();
		properties.put("buildNumber", "1");
		properties.put("revision", "123");
		DeployableArtifact artifact = artifact("/foo/bar.jar", properties);
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar;buildNumber=1;revision=123";
		this.server.expect(requestTo(url)).andRespond(withSuccess());
		this.artifactory.deploy("libs-snapshot-local", artifact);
		this.server.verify();
	}

	@Test
	void deployWhenChecksumMatchesDoesNotUpload() {
		DeployableArtifact artifact = artifact("/foo/bar.jar");
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar";
		this.server.expect(requestTo(url))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(header("X-Checksum-Deploy", "true"))
			.andExpect(header("X-Checksum-Sha1", artifact.getChecksums().getSha1()))
			.andRespond(withSuccess());
		this.artifactory.deploy("libs-snapshot-local", artifact);
		this.server.verify();
	}

	@Test
	void deployWhenChecksumUploadFailsWithHttpClientErrorExceptionUploads() {
		DeployableArtifact artifact = artifact("/foo/bar.jar");
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar";
		this.server.expect(requestTo(url))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(header("X-Checksum-Deploy", "true"))
			.andExpect(header("X-Checksum-Sha1", artifact.getChecksums().getSha1()))
			.andRespond(withStatus(HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE));
		this.server.expect(requestTo(url))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(header("X-Checksum-Sha1", artifact.getChecksums().getSha1()))
			.andRespond(withSuccess());
		this.artifactory.deploy("libs-snapshot-local", artifact);
		this.server.verify();
	}

	@Test
	void deployWhenSmallFileDoesNotUseChecksum() {
		DeployableArtifact artifact = artifact("/foo/bar.jar", "small".getBytes());
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar";
		this.server.expect(requestTo(url))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(noChecksumHeader())
			.andRespond(withSuccess());
		this.artifactory.deploy("libs-snapshot-local", artifact);
		this.server.verify();
	}

	@Test
	void deployWhenFlaky400AndLaterAttemptWorksDeploys() {
		deployWhenFlaky(false, HttpStatus.BAD_REQUEST);
	}

	@Test
	void deployWhenFlaky400AndLaterAttemptsFailThrowsException() {
		assertThatExceptionOfType(RuntimeException.class)
			.isThrownBy(() -> deployWhenFlaky(true, HttpStatus.BAD_REQUEST))
			.withMessageStartingWith("Error deploying artifact");
	}

	@Test
	void deployWhenFlaky404AndLaterAttemptWorksDeploys() {
		deployWhenFlaky(false, HttpStatus.NOT_FOUND);
	}

	@Test
	void deployWhenFlaky404AndLaterAttemptsFailThrowsException() {
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> deployWhenFlaky(true, HttpStatus.NOT_FOUND))
			.withMessageStartingWith("Error deploying artifact");
	}

	@Test
	void deployWhenFlakySocketExceptionAndLaterAttemptWorksDeploys() {
		deployWhenFlaky(false, withException(new SocketException()));
	}

	@Test
	void deployWhenFlakySocketExceptionAndLaterAttemptsFailThrowsException() {
		assertThatExceptionOfType(RuntimeException.class)
			.isThrownBy(() -> deployWhenFlaky(true, withException(new SocketException())))
			.withMessageStartingWith("Error deploying artifact");
	}

	private void deployWhenFlaky(boolean fail, HttpStatus flakyStatus) {
		deployWhenFlaky(fail, withStatus(flakyStatus));
	}

	private void deployWhenFlaky(boolean fail, ResponseCreator failResponse) {
		DeployableArtifact artifact = artifact("/foo/bar.jar");
		String url = "https://repo.example.com/libs-snapshot-local/foo/bar.jar";
		try {
			this.server.expect(requestTo(url))
				.andExpect(method(HttpMethod.PUT))
				.andExpect(header("X-Checksum-Deploy", "true"))
				.andExpect(header("X-Checksum-Sha1", artifact.getChecksums().getSha1()))
				.andRespond(withStatus(HttpStatus.NOT_FOUND));
			this.server.expect(requestTo(url)).andRespond(failResponse);
			this.server.expect(requestTo(url)).andRespond(failResponse);
			this.server.expect(requestTo(url)).andRespond(fail ? failResponse : withStatus(HttpStatus.OK));
			this.artifactory.deploy("libs-snapshot-local", artifact);
		}
		finally {
			this.server.verify();
		}
	}

	private RequestMatcher noChecksumHeader() {
		return (request) -> assertThat(request.getHeaders().keySet()).doesNotContain("X-Checksum-Deploy");
	}

	@Test
	void addAddsBuildInfo() {
		this.server.expect(requestTo("https://repo.example.com/api/build"))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(content().contentType(MediaType.APPLICATION_JSON))
			.andExpect(jsonContent(getResource("payload/build-info.json")))
			.andRespond(withSuccess());
		BuildArtifact artifact = new BuildArtifact("jar", "a9993e364706816aba3e25717850c26c9cd0d89d",
				"900150983cd24fb0d6963f7d28e17f72", "foo.jar");
		List<BuildArtifact> artifacts = Collections.singletonList(artifact);
		Vcs vcs = new Vcs("b8993e365706816aba4f25717851a18c9cd0d873");
		List<BuildModule> modules = Collections
			.singletonList(new BuildModule("com.example.module:my-module:1.0.0-SNAPSHOT", artifacts));
		Instant started = ZonedDateTime.parse("2014-09-30T12:00:19.893Z", DateTimeFormatter.ISO_DATE_TIME).toInstant();
		this.artifactory.addBuildRun(null, "my-build",
				new BuildRun(5678, started, URI.create("https://ci.example.com"), vcs, modules));
		this.server.verify();
	}

	@Test
	void addWithProjectAddsBuildInfo() {
		this.server.expect(requestTo("https://repo.example.com/api/build?project=my-project"))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(content().contentType(MediaType.APPLICATION_JSON))
			.andExpect(jsonContent(getResource("payload/build-info.json")))
			.andRespond(withSuccess());
		BuildArtifact artifact = new BuildArtifact("jar", "a9993e364706816aba3e25717850c26c9cd0d89d",
				"900150983cd24fb0d6963f7d28e17f72", "foo.jar");
		List<BuildArtifact> artifacts = Collections.singletonList(artifact);
		Vcs vcs = new Vcs("b8993e365706816aba4f25717851a18c9cd0d873");
		List<BuildModule> modules = Collections
			.singletonList(new BuildModule("com.example.module:my-module:1.0.0-SNAPSHOT", artifacts));
		Instant started = ZonedDateTime.parse("2014-09-30T12:00:19.893Z", DateTimeFormatter.ISO_DATE_TIME).toInstant();
		this.artifactory.addBuildRun("my-project", "my-build",
				new BuildRun(5678, started, URI.create("https://ci.example.com"), vcs, modules));
		this.server.verify();
	}

	private RequestMatcher jsonContent(Resource expected) {
		return (request) -> {
			String actualJson = ((MockClientHttpRequest) request).getBodyAsString();
			String expectedJson = FileCopyUtils
				.copyToString(new InputStreamReader(expected.getInputStream(), Charset.forName("UTF-8")));
			assertJson(actualJson, expectedJson);
		};
	}

	private void assertJson(String actualJson, String expectedJson) throws AssertionError {
		try {
			JSONAssert.assertEquals(expectedJson, actualJson, true);
		}
		catch (JSONException ex) {
			throw new AssertionError(ex.getMessage(), ex);
		}
	}

	private Resource getResource(String path) {
		return new ClassPathResource(path, getClass());
	}

	private DeployableArtifact artifact(String path) {
		return artifact(path, BYTES, null);
	}

	private DeployableArtifact artifact(String path, byte[] bytes) {
		return artifact(path, bytes, null);
	}

	private DeployableArtifact artifact(String path, Map<String, String> properties) {
		return artifact(path, BYTES, properties);
	}

	private DeployableArtifact artifact(String path, byte[] bytes, Map<String, String> properties) {
		File artifact = new File(this.tempDir, path);
		artifact.getParentFile().mkdirs();
		try {
			Files.write(artifact.toPath(), bytes);
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		return new DeployableFileArtifact(path, artifact, properties, null);
	}

}
