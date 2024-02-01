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

package io.spring.github.actions.artifactorydeploy.artifactory;

import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link Configuration} for Artifactory-related classes.
 *
 * @author Andy Wilkinson
 */
@Configuration(proxyBeanMethods = false)
class ArtifactoryConfiguration {

	@Bean
	Artifactory artifactory(ArtifactoryDeployProperties properties, RestTemplateBuilder restTemplateBuilder) {
		return new HttpArtifactory(restTemplateBuilder, properties.server().uri(), properties.server().username(),
				properties.server().password());
	}

	@Bean
	@ConfigurationPropertiesBinding
	StringToArtifactPropertiesConverter artifactPropertiesConverter() {
		return new StringToArtifactPropertiesConverter();
	}

}
