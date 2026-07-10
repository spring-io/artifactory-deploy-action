/*
 * Copyright 2017-2025 the original author or authors.
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
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.spring.artifactory.deploy.artifactory.payload.BuildModule;
import io.spring.artifactory.deploy.artifactory.payload.CreatedReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.DeployableArtifact;
import io.spring.artifactory.deploy.artifactory.payload.PromotedReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.Promotion;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundlePromotion;
import io.spring.artifactory.deploy.artifactory.payload.Vcs;

import org.springframework.util.Assert;

/**
 * Provides access to Artifactory.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Gabriel Petrovay
 * @author Andy Wilkinson
 * @see HttpArtifactory
 */
public interface Artifactory {

	/**
	 * Deploy the specified artifact to the repository.
	 * @param repository the name of the repository
	 * @param artifact the artifact to deploy
	 * @see <a href="https://docs.jfrog.com/artifactory/reference/deployartifact">JFrog
	 * API documentation</a>
	 */
	void deploy(String repository, DeployableArtifact artifact);

	/**
	 * Adds a build run.
	 * @param project the name of the project, if any, that should store the build run's
	 * info
	 * @param buildName the name of the build
	 * @param buildRun the build run to add
	 * @see <a href="https://docs.jfrog.com/integrations/reference/uploadbuild">JFrog API
	 * documentation</a>
	 */
	void addBuildRun(String project, String buildName, BuildRun buildRun);

	/**
	 * Promotes a build.
	 * @param buildName the build name
	 * @param buildNumber the build number
	 * @param project the project
	 * @param promotion the promotion to perform
	 * @see <a href="https://docs.jfrog.com/integrations/reference/promoteBuild">JFrog API
	 * documentation</a>
	 */
	void promoteBuild(String buildName, String buildNumber, String project, Promotion promotion);

	/**
	 * Removes builds stored in Artifactory.
	 * @param buildName the build name
	 * @param buildNumber the build number to delete
	 * @param project the project
	 * @param delete any additional deletion operations
	 * @see <a href="https://docs.jfrog.com/integrations/reference/deletebuilds">JFrog API
	 * documentation</a>
	 */
	default void deleteBuild(String buildName, String buildNumber, String project, Delete... delete) {
		deleteBuild(buildName, BuildNumbers.of(buildNumber), project, delete);
	}

	/**
	 * Removes builds stored in Artifactory.
	 * @param buildName the build name
	 * @param buildNumbers the build numbers to delete
	 * @param project the project
	 * @param delete any additional deletion operations
	 * @see <a href="https://docs.jfrog.com/integrations/reference/deletebuilds">JFrog API
	 * documentation</a>
	 */
	void deleteBuild(String buildName, BuildNumbers buildNumbers, String project, Delete... delete);

	/**
	 * Create a release bundle.
	 * @param async whether to create the bundle asynchronously
	 * @param failFast whether to fail fast on errors
	 * @param project the project key used to determine the Release Bundles repository
	 * @param repositoryKey the Release Bundles repository identifier that identifies
	 * where a Release Bundle version resides
	 * @param releaseBundle the release bundle to create
	 * @return details of the created release bundle
	 */
	CreatedReleaseBundle createReleaseBundle(boolean async, boolean failFast, String project, String repositoryKey,
			ReleaseBundle releaseBundle);

	/**
	 * Deletes a specific Release Bundle v2 version.
	 * @param name the release bundle name
	 * @param version the release bundle version
	 * @param project the project key used to determine the Release Bundles repository
	 * @param repositoryKey the Release Bundles repository identifier that identifies
	 * where a Release Bundle version resides
	 * @param async whether to create the bundle asynchronously
	 * @param isRemoteDeleteByDistribution whether this is a remote delete by distribution
	 */
	void deleteReleaseBundle(String name, String version, String project, String repositoryKey, boolean async,
			boolean isRemoteDeleteByDistribution);

	/**
	 * Promote a specific Release Bundle v2 version.
	 * @param name the release bundle name
	 * @param version the release bundle version
	 * @param async whether to create the bundle asynchronously
	 * @param operation the operation to perform
	 * @param project the project key used to determine the Release Bundles repository
	 * @param repositoryKey the Release Bundles repository identifier that identifies
	 * where a Release Bundle version resides
	 * @param releaseBundlePromotion promotion details
	 * @return details of the promoted bundle
	 */
	PromotedReleaseBundle promoteReleaseBundle(String name, String version, boolean async,
			PromoteReleaseBundleOperation operation, String project, String repositoryKey,
			ReleaseBundlePromotion releaseBundlePromotion);

	/**
	 * A build run.
	 *
	 * @param number the number of the build
	 * @param started the instant at which the build started
	 * @param uri the URI of the build, typically on a CI server
	 * @param vcs the version control system that was used for the build
	 * @param modules the modules produced by the build
	 */
	record BuildRun(String number, Instant started, URI uri, Vcs vcs, List<BuildModule> modules) {
	}

	/**
	 * A set of build numbers.
	 *
	 * @param value the build numbers
	 */
	record BuildNumbers(Set<String> value) {

		/**
		 * Create a new {@link BuildNumbers} instance.
		 * @param value the build numbers value
		 */
		public BuildNumbers {
			Assert.notEmpty(value, "'value' must not be empty");
		}

		static BuildNumbers of(String... buildNumbers) {
			return new BuildNumbers(Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(buildNumbers))));
		}

	}

	/**
	 * Delete operations.
	 */
	enum Delete {

		/**
		 * Delete artifacts.
		 */
		ARTIFACTS,

		/**
		 * Delete all builds.
		 */
		ALL_BUILDS

	}

	/**
	 * Promote release bundle operations.
	 */
	enum PromoteReleaseBundleOperation {

		/**
		 * Copy.
		 */
		COPY,

		/**
		 * Move.
		 */
		MOVE

	}

}
