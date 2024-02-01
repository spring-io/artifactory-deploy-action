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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.util.Assert;

/**
 * A single module included in {@link BuildInfo}.
 *
 * @param id the id of the module ({@code groupId:artifactId:version})
 * @param artifacts the artifacts of the module
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 */
public record BuildModule(String id, List<BuildArtifact> artifacts) {

	public BuildModule(String id, List<BuildArtifact> artifacts) {
		Assert.hasText(id, "ID must not be empty");
		this.id = id;
		this.artifacts = (artifacts != null) ? Collections.unmodifiableList(new ArrayList<>(artifacts))
				: Collections.emptyList();
	}

}
