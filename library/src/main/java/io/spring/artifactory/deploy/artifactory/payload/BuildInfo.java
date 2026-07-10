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

package io.spring.artifactory.deploy.artifactory.payload;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.util.Assert;

/**
 * Build information for Artifactory.
 *
 * @param name name of the build
 * @param number number of the build
 * @param agent CI server that performed the build
 * @param buildAgent Agent that deployed the build
 * @param started Instant at which the build start
 * @param url URL of the build on the CI server
 * @param vcs version control systems used for the build
 * @param modules modules produced by the build
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 */
public record BuildInfo(String name, String number, CiAgent agent, BuildAgent buildAgent,
		@JsonTimestamp Instant started, String url, List<Vcs> vcs, List<BuildModule> modules) {

	/**
	 * Creates a new {@link BuildInfo} with default CI and build agents.
	 * @param name name of the build
	 * @param number number of the build
	 * @param started instant at which the build started
	 * @param url url of the build on the CI server
	 * @param vcs version control system used for the build
	 * @param modules modules produced by the build
	 */
	public BuildInfo(String name, String number, Instant started, String url, Vcs vcs, List<BuildModule> modules) {
		this(name, number, new CiAgent(), new BuildAgent(), started, url, (vcs != null) ? List.of(vcs) : null, modules);
	}

	/**
	 * Creates a new {@link BuildInfo} with all fields.
	 * @param name name of the build
	 * @param number number of the build
	 * @param agent ci server that performed the build
	 * @param buildAgent agent that deployed the build
	 * @param started instant at which the build started
	 * @param url url of the build on the CI server
	 * @param vcs version control systems used for the build
	 * @param modules modules produced by the build
	 */
	public BuildInfo(String name, String number, CiAgent agent, BuildAgent buildAgent, Instant started, String url,
			List<Vcs> vcs, List<BuildModule> modules) {
		Assert.hasText(name, "'name' must not be empty");
		Assert.hasText(number, "'number' must not be empty");
		this.name = name;
		this.number = number;
		this.agent = agent;
		this.buildAgent = buildAgent;
		this.started = (started != null) ? started : Instant.now();
		this.url = url;
		this.vcs = (vcs != null) ? Collections.unmodifiableList(vcs) : Collections.emptyList();
		this.modules = (modules != null) ? Collections.unmodifiableList(new ArrayList<>(modules))
				: Collections.emptyList();
	}

}
