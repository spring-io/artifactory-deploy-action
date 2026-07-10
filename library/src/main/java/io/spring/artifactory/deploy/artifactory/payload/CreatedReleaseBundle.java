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

import tools.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Details of a newly created release bundle.
 *
 * @param repositoryKey the repository key, for example {@code release-bundles-v2}.
 * @param releaseBundleName the release bundle name
 * @param releaseBundleVersion the release bundle version
 * @param created the creation date
 * @param tag the tag
 * @author Phillip Webb
 */
@JsonNaming(SnakeCaseStrategy.class)
public record CreatedReleaseBundle(String repositoryKey, String releaseBundleName, String releaseBundleVersion,
		@JsonTimestamp Instant created, String tag) {

}
