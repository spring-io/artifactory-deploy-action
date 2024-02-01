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

package io.spring.github.actions.artifactorydeploy.artifactory.payload;

import org.springframework.util.Assert;

/**
 * A single build artifact included in {@link BuildInfo}.
 *
 * @param type type of the artifact
 * @param sha1 SHA1 checksum of the artifact
 * @param md5 MD5 checksum of the artifact
 * @param name name of the artifact
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 * @see BuildInfo
 */
public record BuildArtifact(String type, String sha1, String md5, String name) {

	public BuildArtifact(String type, String sha1, String md5, String name) {
		Assert.hasText(type, "Type must not be empty");
		Assert.hasText(sha1, "SHA1 must not be empty");
		Assert.hasText(md5, "MD5 must not be empty");
		Assert.hasText(name, "Name must not be empty");
		this.type = type;
		this.sha1 = sha1;
		this.md5 = md5;
		this.name = name;
	}

}
