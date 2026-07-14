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
	@JsonSubTypes({ @JsonSubTypes.Type(value = BuildsSource.class, name = "builds"),
			@JsonSubTypes.Type(value = ReleaseBundlesSource.class, name = "release_bundles") })
	public sealed interface Source {

	}

	/**
	 * Source from published builds.
	 *
	 * @param builds the builds
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record BuildsSource(List<BuildSource> builds) implements Source {

		/**
		 * Create a new {@link BuildsSource} instance.
		 * @param builds the builds
		 */
		public BuildsSource {
			Assert.notEmpty(builds, "'builds' must not be empty");
		}

		/**
		 * Factory method to create {@link BuildsSource} from the given values.
		 * @param builds the builds to include
		 * @return a new {@link BuildsSource} instance
		 */
		public static BuildsSource of(BuildSource... builds) {
			return new BuildsSource(List.of(builds));
		}

	}

	/**
	 * A single build source.
	 *
	 * @param buildName the build name
	 * @param buildNumber the build number
	 * @param buildRepository the build repository, for example {@code spring-build-info}
	 * @param includeDependencies if dependencies are included
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record BuildSource(String buildName, String buildNumber, String buildRepository,
			Boolean includeDependencies) {

		/**
		 * Create a new {@link BuildSource} instance.
		 * @param buildName the build name
		 * @param buildNumber the build number
		 * @param buildRepository the build repository, for example
		 * {@code spring-build-info}
		 * @param includeDependencies if dependencies are included
		 */
		public BuildSource {
			Assert.hasText(buildName, "'buildName' must not be empty");
			Assert.hasText(buildNumber, "'buildNumber' must not be empty");
		}

		/**
		 * Return an updated {@link BuildSource} that uses the standard
		 * {@code artifactory-build-info} build repository.
		 * @return a new {@link BuildSource} instance
		 */
		public BuildSource withBuildInfoRepository() {
			return withBuildInfoRepository(null);
		}

		/**
		 * Return an updated {@link BuildSource} that uses a project specific
		 * {@code build-info} build repository.
		 * @param project the project or {@code null} to use the default build-info
		 * repository
		 * @return a new {@link BuildSource} instance
		 */
		public BuildSource withBuildInfoRepository(String project) {
			String buildRepository = "%s-build-info".formatted(StringUtils.hasText(project) ? project : "artifactory");
			return new BuildSource(buildName(), buildNumber(), buildRepository, includeDependencies());
		}

		/**
		 * Return an updated {@link BuildSource} with a new include dependencies value.
		 * @param includeDependencies the new include dependencies value
		 * @return a new {@link BuildSource} instance
		 */
		public BuildSource withIncludeDependencies(Boolean includeDependencies) {
			return new BuildSource(buildName(), buildNumber(), buildRepository(), includeDependencies);
		}

		/**
		 * Factory method to create a new {@link BuildSource} using the default build
		 * repository.
		 * @param buildName the build name
		 * @param buildNumber the build number
		 * @return a new Build instance
		 */
		public static BuildSource of(String buildName, String buildNumber) {
			return new BuildSource(buildName, buildNumber, null, null).withBuildInfoRepository();
		}

	}

	/**
	 * Source from release bundles.
	 *
	 * @param releaseBundles the release bundles
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record ReleaseBundlesSource(List<ReleaseBundleSource> releaseBundles) implements Source {
		/**
		 * Create a new {@link BuildsSource} instance.
		 * @param releaseBundles the release bundles
		 */
		public ReleaseBundlesSource {
			Assert.notEmpty(releaseBundles, "'releaseBundles' must not be empty");
		}

		/**
		 * Factory method to create {@link BuildsSource} from the given values.
		 * @param releaseBundles the release bundles to include
		 * @return a new {@link BuildsSource} instance
		 */
		public static ReleaseBundlesSource of(ReleaseBundleSource... releaseBundles) {
			return new ReleaseBundlesSource(List.of(releaseBundles));
		}
	}

	/**
	 * A single release bundle source.
	 *
	 * @param releaseBundleName the release bundle name
	 * @param releaseBundleVersion the release bundle version
	 * @param repositoryKey the repository key
	 * @param projectKey the project key
	 */
	@JsonNaming(SnakeCaseStrategy.class)
	public record ReleaseBundleSource(String releaseBundleName, String releaseBundleVersion, String repositoryKey,
			String projectKey) {

		/**
		 * Create a new {@link ReleaseBundleSource}.
		 * @param releaseBundleName the release bundle name
		 * @param releaseBundleVersion the release bundle version
		 * @param repositoryKey the repository key
		 * @param projectKey the project key
		 */
		public ReleaseBundleSource {
			Assert.hasText(releaseBundleName, "'releaseBundleName' must not be empty");
			Assert.hasText(releaseBundleVersion, "'releaseBundleVersion' must not be empty");
		}

		/**
		 * Return a new {@link ReleaseBundleSource} with an updated project key.
		 * @param projectKey the updated project key
		 * @return a new {@link ReleaseBundleSource} instance
		 */
		public ReleaseBundleSource withProjectKey(String projectKey) {
			return new ReleaseBundleSource(releaseBundleName(), releaseBundleVersion(), repositoryKey(), projectKey);
		}

		/**
		 * Return a new {@link ReleaseBundleSource} with an updated repository key.
		 * @param repositoryKey the updated repository key
		 * @return a new {@link ReleaseBundleSource} instance
		 */
		public ReleaseBundleSource withRepositoryKey(String repositoryKey) {
			return new ReleaseBundleSource(releaseBundleName(), releaseBundleVersion(), repositoryKey, projectKey());
		}

		/**
		 * Factory method to create a new {@link ReleaseBundleSource}.
		 * @param releaseBundleName the release bundle name
		 * @param releaseBundleVersion the release bundle version
		 * @return a new {@link ReleaseBundleSource} instance
		 */
		public static ReleaseBundleSource of(String releaseBundleName, String releaseBundleVersion) {
			return new ReleaseBundleSource(releaseBundleName, releaseBundleVersion, null, null);
		}

	}

}
