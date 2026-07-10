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

import java.util.Collections;

import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.Source;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ReleaseBundle}.
 *
 * @author Phillip Webb
 */
@JsonTest
@ActiveProfiles("test")
class ReleaseBundleTests {

	private static final Source.Builds BUILDS_SOURCE = Source.Builds
		.of(new Source.Build("my-build", "2.3.4", "spring-build-info", null));

	@Autowired
	private JacksonTester<ReleaseBundle> json;

	@Test
	void createWhenReleaseBundleNameIsNullThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundle(null, "v", null, BUILDS_SOURCE, null))
			.withMessage("'releaseBundleName' must not be empty");
	}

	@Test
	void createWhenReleaseBundleVersionIsNullThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundle("b", null, null, BUILDS_SOURCE, null))
			.withMessage("'releaseBundleVersion' must not be empty");
	}

	@Test
	void createWhenSourceIsNullThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundle("b", "v", null, null, null))
			.withMessage("'source' must not be null");
	}

	@Test
	void writeSerializesJson() throws Exception {
		ReleaseBundle releaseBundle = new ReleaseBundle("my-bundle", "1.2.3", null, BUILDS_SOURCE, "my-tag");
		assertThat(this.json.write(releaseBundle)).isEqualToJson("release-bundle-with-build.json");
	}

	@Nested
	class BuildsTests {

		@Test
		void createWhenBuildsIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new Source.Builds(null))
				.withMessage("'builds' must not be empty");
		}

		@Test
		void createWhenBuildsIsEmptyThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new Source.Builds(Collections.emptyList()))
				.withMessage("'builds' must not be empty");
		}

	}

	@Nested
	class BuildTests {

		@Test
		void createWhenBuildNameIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new Source.Build(null, "1", null, null))
				.withMessage("'buildName' must not be empty");
		}

		@Test
		void createWhenBuildNumberIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new Source.Build("n", null, null, null))
				.withMessage("'buildNumber' must not be empty");
		}

	}

}
