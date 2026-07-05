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
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonFormat;

import org.springframework.util.CollectionUtils;

/**
 * Promotion information.
 *
 * @param status the new status of the build
 * @param comment the comment describing the reason for the promotion
 * @param ciUser the user that invoked promotion from the CI server
 * @param timestamp the time when the promotion command was received
 * @param dryRun if promotion is a dry-run only
 * @param sourceRepo the repository from which the build contents will be copied or moved
 * @param targetRepo the target repository to which the build contents will be copied or
 * moved
 * @param copy if artifacts should be copied
 * @param artifacts whether to move/copy the build's artifacts.
 * @param dependencies whether to move/copy the build's dependencies
 * @param scopes an array of dependency scopes
 * @author Phillip Webb
 */
public record Promotion(String status, String comment, String ciUser,
		@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX",
				timezone = "UTC") Instant timestamp,
		Boolean dryRun, String sourceRepo, String targetRepo, Boolean copy, Boolean artifacts, Boolean dependencies,
		Set<String> scopes) {

	/**
	 * Create a new {@link Promotion} instance.
	 * @param status the new status of the build
	 * @param comment the comment describing the reason for the promotion
	 * @param ciUser the user that invoked promotion from the CI server
	 * @param timestamp the time when the promotion command was received
	 * @param dryRun if promotion is a dry-run only
	 * @param sourceRepo the repository from which the build contents will be copied or
	 * moved
	 * @param targetRepo the target repository to which the build contents will be copied
	 * or moved
	 * @param copy if artifacts should be copied
	 * @param artifacts whether to move/copy the build's artifacts.
	 * @param dependencies whether to move/copy the build's dependencies
	 * @param scopes an array of dependency scopes
	 */
	public Promotion {
		scopes = CollectionUtils.isEmpty(scopes) ? Collections.emptySet()
				: Collections.unmodifiableSet(new TreeSet<>(scopes));
	}

	/**
	 * Create a new {@link Promotion} instance.
	 * @param sourceRepo the repository from which the build contents will be copied or
	 * moved
	 * @param targetRepo the target repository to which the build contents will be copied
	 * or moved
	 */
	public Promotion(String sourceRepo, String targetRepo) {
		this(null, null, null, null, null, sourceRepo, targetRepo, null, null, null, null);
	}

}
