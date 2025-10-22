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

package io.spring.github.actions.artifactorydeploy.artifactory;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import io.spring.github.actions.artifactorydeploy.artifactory.payload.BuildModule;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.Vcs;

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
	 */
	void deploy(String repository, DeployableArtifact artifact);

	/**
	 * Adds a build run.
	 * @param project the name of the project, if any, that should store the build run's
	 * info
	 * @param buildName the name of the build
	 * @param buildRun the build run to add
	 */
	void addBuildRun(String project, String buildName, BuildRun buildRun);

	/**
	 * A build run.
	 *
	 * @param number the number of the build
	 * @param started the instant at which the build started
	 * @param uri the URI of the build, typically on a CI server
	 * @param vcs Version control details
	 * @param modules the modules produced by the build
	 *
	 */
	record BuildRun(int number, Instant started, URI uri, Vcs vcs, List<BuildModule> modules) {
	}

}
