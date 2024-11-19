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

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.Assert;

/**
 * Configuration properties for deploying to Artifactory.
 *
 * @param server server properties
 * @param signing signing properties
 * @param deploy deploy properties
 * @author Andy Wilkinson
 */
@ConfigurationProperties(prefix = "artifactory")
public record ArtifactoryDeployProperties(@DefaultValue ArtifactoryDeployProperties.Server server,
		@DefaultValue ArtifactoryDeployProperties.Signing signing,
		@DefaultValue ArtifactoryDeployProperties.Deploy deploy) {

	public record Server(URI uri, String username, String password) {

		public Server(URI uri, String username, String password) {
			Assert.notNull(uri, "artifactory.server.uri is required");
			this.uri = uri;
			this.username = username;
			this.password = password;
		}

	}

	public record Signing(String key, String passphrase, String keyId) {
	}

	public record Deploy(String project, String folder, String repository, int threads, Deploy.Build build,
			List<Deploy.ArtifactProperties> artifactProperties) {

		public Deploy(String project, String folder, String repository, @DefaultValue("1") int threads,
				@DefaultValue Deploy.Build build, List<Deploy.ArtifactProperties> artifactProperties) {
			Assert.hasText(folder, "artifactory.deploy.folder is required");
			Assert.hasText(repository, "artifactory.deploy.repository is required");
			this.project = project;
			this.folder = folder;
			this.repository = repository;
			this.threads = threads;
			this.build = build;
			this.artifactProperties = (artifactProperties != null) ? artifactProperties : Collections.emptyList();
		}

		public record Build(String name, int number, URI uri) {

			public Build(String name, int number, URI uri) {
				Assert.hasText(name, "artifactory.deploy.build.name is required");
				this.name = name;
				this.number = number;
				this.uri = uri;
			}

		}

		public record ArtifactProperties(List<String> include, List<String> exclude, Map<String, String> properties) {

			public ArtifactProperties(List<String> include, List<String> exclude, Map<String, String> properties) {
				this.include = (include != null) ? include : Collections.emptyList();
				this.exclude = (exclude != null) ? exclude : Collections.emptyList();
				this.properties = (properties != null) ? properties : Collections.emptyMap();
			}

		}

	}

}
