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

import io.spring.artifactory.deploy.Deployer;
import io.spring.artifactory.deploy.artifactory.Artifactory;
import io.spring.artifactory.deploy.io.DirectoryScanner;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link Configuration} for the application.
 *
 * @author Moritz Halbritter
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ArtifactoryDeployProperties.class)
class ApplicationConfiguration {

	private final ArtifactoryDeployProperties properties;

	ApplicationConfiguration(ArtifactoryDeployProperties properties) {
		this.properties = properties;
	}

	@Bean
	Deployer deployer(Artifactory artifactory, DirectoryScanner directoryScanner) {
		return new Deployer(artifactory, directoryScanner, this.properties.server().uri(),
				this.properties.deploy().threads());
	}

}
