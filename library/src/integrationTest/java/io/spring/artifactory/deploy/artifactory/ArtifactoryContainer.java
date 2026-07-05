/*
 * Copyright 2026 the original author or authors.
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

import java.net.URI;
import java.time.Duration;
import java.util.function.Supplier;

import io.spring.artifactory.deploy.system.Logger;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.client.RestClient;

/**
 * A {@link Container} implementation for JFrog Artifactory OSS.
 *
 * @author Stephane Nicoll
 */
class ArtifactoryContainer extends GenericContainer<ArtifactoryContainer> {

	private final Supplier<RestClient> restClientSupplier = SingletonSupplier
		.of(() -> createRestClient(RestClient.builder()));

	ArtifactoryContainer() {
		super("releases-docker.jfrog.io/jfrog/artifactory-oss:7.146.17");
		withExposedPorts(8081, 8082)
			.withClasspathResourceMapping("system.yml", "/opt/jfrog/artifactory/var/etc/system.yaml",
					BindMode.READ_ONLY)
			.withClasspathResourceMapping("artifactory.config.import.yml",
					"/opt/jfrog/artifactory/var/etc/artifactory/artifactory.config.import.yml", BindMode.READ_ONLY)
			.waitingFor(Wait.forHttp("/router/api/v1/system/health")
				.forPort(8082)
				.forStatusCode(200)
				.withStartupTimeout(Duration.ofMinutes(1)));
	}

	/**
	 * Return the username to access the REST API.
	 * @return the username
	 */
	String getUsername() {
		return "admin";
	}

	/**
	 * Return the password to access the REST API.
	 * @return the password
	 */
	String getPassword() {
		return "password";
	}

	/**
	 * Return the base URL of the artifactory server.
	 * @return the base url
	 */
	URI getBaseUrl() {
		return URI.create("http://" + getHost() + ":" + getMappedPort(8081) + "/artifactory");
	}

	/**
	 * Return an {@link Artifactory} that can be used against this container.
	 * @return an artifactory suitable for this container
	 */
	Artifactory getArtifactory() {
		return new HttpArtifactory(Logger.console(true), RestClient.builder(), getBaseUrl(), getUsername(),
				getPassword());
	}

	/**
	 * Return a {@link RestClient} that is configured to access the artifactory instance
	 * managed by this container.
	 * @return a rest client to access artifactory
	 */
	RestClient getRestClient() {
		return this.restClientSupplier.get();
	}

	/**
	 * Create a {@link RestClient} using the given rest client builder.
	 * @param builder the builder to use
	 * @return a rest client to access artifactory
	 */
	RestClient createRestClient(RestClient.Builder builder) {
		return builder.baseUrl(getBaseUrl())
			.defaultHeaders((headers) -> headers.setBasicAuth(getUsername(), getPassword()))
			.build();
	}

}
