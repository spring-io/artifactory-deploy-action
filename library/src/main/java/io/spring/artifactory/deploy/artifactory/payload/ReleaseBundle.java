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

import java.util.List;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.Source.Builds;
import tools.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import tools.jackson.databind.annotation.JsonNaming;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A release bundle.
 *
 * @param releaseBundleName the release bundle name
 * @param releaseBundleVersion the release bundle version
 * @param skipDockerManifestResolution whether to skip Docker manifest resolution during
 * bundle creation
 * @param source the source of the bundle
 * @param tag an optional tag for the bundle
 * @author Phillip Webb
 */
@JsonNaming(SnakeCaseStrategy.class)
public record ReleaseBundle(String releaseBundleName, String releaseBundleVersion, Boolean skipDockerManifestResolution,
		@JsonTypeInfo(use = Id.NAME, include = As.EXTERNAL_PROPERTY, property = "source_type") Source source,
		String tag) {

	/**
	 * Create a new {@link ReleaseBundle} instance.
	 * @param releaseBundleName the release bundle name
	 * @param releaseBundleVersion the release bundle version
	 * @param skipDockerManifestResolution whether to skip Docker manifest resolution
	 * during bundle creation
	 * @param source the source of the bundle
	 * @param tag an optional tag for the bundle
	 */
	public ReleaseBundle {
		Assert.hasText(releaseBundleName, "'releaseBundleName' must not be empty");
		Assert.hasText(releaseBundleVersion, "'releaseBundleVersion' must not be empty");
		Assert.notNull(source, "'source' must not be null");
	}

	/**
	 * Sources that can be used to create a release bundle.
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	@JsonSubTypes(@JsonSubTypes.Type(value = Builds.class, name = "builds"))
	public sealed interface Source {

		/**
		 * Source from published builds.
		 *
		 * @param builds the builds
		 */
		record Builds(List<Build> builds) implements Source {

			/**
			 * Create a new {@link Builds} instance.
			 * @param builds the builds
			 */
			public Builds {
				Assert.notEmpty(builds, "'builds' must not be empty");
			}

			/**
			 * Factory method to create {@link Builds} from the given values.
			 * @param builds the builds to include
			 * @return a new {@link Builds} instance
			 */
			public static Builds of(Build... builds) {
				return new Builds(List.of(builds));
			}

		}

		/**
		 * A single build source.
		 *
		 * @param buildName the build name
		 * @param buildNumber the build number
		 * @param buildRepository the build repository, for example
		 * {@code spring-build-info}
		 * @param includeDependencies if dependencies are included
		 */
		@JsonNaming(SnakeCaseStrategy.class)
		record Build(String buildName, String buildNumber, String buildRepository, Boolean includeDependencies) {

			/**
			 * Create a new {@link Build} instance.
			 * @param buildName the build name
			 * @param buildNumber the build number
			 * @param buildRepository the build repository, for example
			 * {@code spring-build-info}
			 * @param includeDependencies if dependencies are included
			 */
			public Build {
				Assert.hasText(buildName, "'buildName' must not be empty");
				Assert.hasText(buildNumber, "'buildNumber' must not be empty");
			}

			/**
			 * Return an updated {@link Build} that uses the standard
			 * {@code artifactory-build-info} build repository.
			 * @return a new {@link Build} instance
			 */
			public Build withBuildInfoRepository() {
				return withBuildInfoRepository(null);
			}

			/**
			 * Return an updated {@link Build} that uses a project specific
			 * {@code build-info} build repository.
			 * @param project the project or {@code null} to use the default build-info
			 * repository
			 * @return a new {@link Build} instance
			 */
			public Build withBuildInfoRepository(String project) {
				String buildRepository = "%s-build-info"
					.formatted(StringUtils.hasText(project) ? project : "artifactory");
				return new Build(buildName(), buildNumber(), buildRepository, includeDependencies());
			}

			/**
			 * Return an updated {@link Build} with a new include dependencies value.
			 * @param includeDependencies the new include dependencies value
			 * @return a new {@link Build} instance
			 */
			public Build withIncludeDependencies(Boolean includeDependencies) {
				return new Build(buildName(), buildNumber(), buildRepository(), includeDependencies);
			}

			/**
			 * Factory method to create a new {@link Build} using the default build
			 * repository.
			 * @param buildName the build name
			 * @param buildNumber the build number
			 * @return a new Build instance
			 */
			public static Build of(String buildName, String buildNumber) {
				return new Build(buildName, buildNumber, null, null).withBuildInfoRepository();
			}

		}

	}

}
