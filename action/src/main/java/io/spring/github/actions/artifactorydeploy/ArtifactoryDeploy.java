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

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import io.spring.artifactory.deploy.Deployer.ArtifactProperties;
import io.spring.artifactory.deploy.Deployer.Signing;
import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.util.CollectionUtils;

/**
 * Main Application entry point.
 *
 * @author Phillip Webb
 * @author Andy Wilkinson
 */
@SpringBootApplication
@EnableConfigurationProperties(ArtifactoryDeployProperties.class)
public class ArtifactoryDeploy {

	public static void main(String[] args) {
		ConfigurableApplicationContext app = SpringApplication.run(ArtifactoryDeploy.class, args);
		ArtifactoryDeployProperties properties = app.getBean(ArtifactoryDeployProperties.class);
		app.getBean(io.spring.artifactory.deploy.Deployer.class)
			.deploy(properties.deploy().repository(), properties.deploy().build().number(),
					properties.deploy().build().name(), properties.deploy().build().uri(),
					properties.deploy().project(), properties.vcs().revision(), Path.of(properties.deploy().folder()),
					mapArtifactProperties(properties.deploy().artifactProperties()), mapSigning(properties.signing()));
	}

	private static Signing mapSigning(ArtifactoryDeployProperties.Signing signing) {
		if (signing == null) {
			return null;
		}
		return new Signing(signing.key(), signing.passphrase(), signing.keyId());
	}

	private static List<ArtifactProperties> mapArtifactProperties(List<Deploy.ArtifactProperties> artifactProperties) {
		if (CollectionUtils.isEmpty(artifactProperties)) {
			return Collections.emptyList();
		}
		return artifactProperties.stream()
			.map((property) -> new ArtifactProperties(property.include(), property.exclude(), property.properties()))
			.toList();
	}

}
