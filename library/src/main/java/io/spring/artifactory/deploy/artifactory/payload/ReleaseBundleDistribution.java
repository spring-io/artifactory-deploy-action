/*
 * Copyright 2017-present the original author or authors.
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

package io.spring.artifactory.deploy.artifactory.payload;

import java.util.List;

import tools.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Release bundle promotion information.
 *
 * @param autoCreateMissingRepositories whether to create missing repositories
 * automatically on the distribution targets
 * @param distributionRules filters defining which distribution targets to include
 * @param modifications path mapping for the artifacts on the distribution targets
 * @author Phillip Webb
 */
@JsonNaming(SnakeCaseStrategy.class)
public record ReleaseBundleDistribution(Boolean autoCreateMissingRepositories, List<DistributionRule> distributionRules,
		Modifications modifications) {

	/**
	 * A distribution rule.
	 *
	 * @param siteName a wildcard filter for a site name
	 * @param cityName a wildcard filter for a city name
	 * @param countryCodes one or more filters for country codes
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record DistributionRule(String siteName, String cityName, List<String> countryCodes) {

	}

	/**
	 * Modifications to make when distributing.
	 *
	 * @param defaultPathMappingByLastPromotion if the repositories used for the most
	 * recent promotion of the release bundle version are provided as the path mapping
	 * @param mappings the input and output regex mapping pairs
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record Modifications(Boolean defaultPathMappingByLastPromotion, List<Mapping> mappings) {

	}

	/**
	 * A single mapping pair.
	 *
	 * @param input the regex mapping to apply to the input. For example
	 * {@code "spring-enterprise-maven-prod-local/(.*)"}
	 * @param output the regex mapping to apply to the output. For example
	 * {@code "spring-enterprise/$1"}
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record Mapping(String input, String output) {

	}
}
