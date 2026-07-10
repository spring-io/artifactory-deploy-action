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

package io.spring.artifactory.deploy.artifactory.payload;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Details of a newly promoted release bundle.
 *
 * @author Phillip Webb
 * @param repositoryKey the repository key where the bundle is stored
 * @param releaseBundleName the name of the release bundle
 * @param releaseBundleVersion the version of the release bundle
 * @param environment the target environment for the promotion
 * @param includedRepositoryKeys the specific repositories included in the promotion
 * @param excludedRepositoryKeys the specific repositories excluded in the promotion
 * @param artifactAdditionalProperties the properties associated with a bundle item
 * @param created the timestamp when the promotion was created
 * @param createdMillis the timestamp when the promotion was created (in milliseconds)
 * @param sourceEnvironment the source environment from which the Release Bundle version
 * was promoted
 */
@JsonNaming(SnakeCaseStrategy.class)
public record PromotedReleaseBundle(String repositoryKey, String releaseBundleName, String releaseBundleVersion,
		String environment, List<String> includedRepositoryKeys, List<String> excludedRepositoryKeys,
		Map<String, String> artifactAdditionalProperties, @JsonTimestamp Instant created, Long createdMillis,
		String sourceEnvironment) {

}
