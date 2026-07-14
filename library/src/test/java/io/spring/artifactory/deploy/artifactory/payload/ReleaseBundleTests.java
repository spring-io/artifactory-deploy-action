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

import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.BuildSource;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.BuildsSource;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.ReleaseBundleSource;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundle.ReleaseBundlesSource;
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

	private static final BuildsSource BUILDS_SOURCE = BuildsSource
		.of(new BuildSource("my-build", "2.3.4", "spring-build-info", null));

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
	void ofCreateBundleWithStandardBuildInfoRepository() {
		assertThat(BuildSource.of("a", "1")).isEqualTo(new BuildSource("a", "1", "artifactory-build-info", null));
	}

	@Test
	void withBuildInfoRepositoryUsesArtifactoryBuildInfoRepository() {
		assertThat(new BuildSource("a", "1", null, null).withBuildInfoRepository())
			.isEqualTo(new BuildSource("a", "1", "artifactory-build-info", null));
	}

	@Test
	void withBuildInfoRepositoryWhenProjectIsNullUsesArtifactoryBuildInfoRepository() {
		assertThat(new BuildSource("a", "1", null, null).withBuildInfoRepository(null))
			.isEqualTo(new BuildSource("a", "1", "artifactory-build-info", null));
	}

	@Test
	void withBuildInfoRepositoryWhenProjectIsNotNullUsesProjectBuildInfoRepository() {
		assertThat(new BuildSource("a", "1", null, null).withBuildInfoRepository("spring"))
			.isEqualTo(new BuildSource("a", "1", "spring-build-info", null));
	}

	@Test
	void withIncludeDependenciesUpdatesIncludeDependencies() {
		assertThat(BuildSource.of("a", "1").withIncludeDependencies(true))
			.isEqualTo(new BuildSource("a", "1", "artifactory-build-info", true));
	}

	@Test
	void writeSerializesJsonWhenHasBuildsSource() throws Exception {
		ReleaseBundle releaseBundle = new ReleaseBundle("my-bundle", "1.2.3", null, BUILDS_SOURCE, "my-tag");
		assertThat(this.json.write(releaseBundle)).isEqualToJson("release-bundle-with-build.json");
	}

	@Test
	void writeSerializesJsonWhenHasReleaseBundlesSource() throws Exception {
		ReleaseBundlesSource releaseBundleSource = ReleaseBundlesSource
			.of(ReleaseBundleSource.of("my-other-bundle", "3.4.5").withProjectKey("my-project"));
		ReleaseBundle releaseBundle = new ReleaseBundle("my-bundle", "1.2.3", null, releaseBundleSource, "my-tag");
		System.out.println(this.json.write(releaseBundle).getJson());
		assertThat(this.json.write(releaseBundle)).isEqualToJson("release-bundle-with-release-bundle.json");
	}

	@Nested
	class BuildsSourceTests {

		@Test
		void createWhenBuildsIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new BuildsSource(null))
				.withMessage("'builds' must not be empty");
		}

		@Test
		void createWhenBuildsIsEmptyThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new BuildsSource(Collections.emptyList()))
				.withMessage("'builds' must not be empty");
		}

	}

	@Nested
	class BuildSourceTests {

		@Test
		void createWhenBuildNameIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new BuildSource(null, "1", null, null))
				.withMessage("'buildName' must not be empty");
		}

		@Test
		void createWhenBuildNumberIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new BuildSource("n", null, null, null))
				.withMessage("'buildNumber' must not be empty");
		}

	}

	@Nested
	class ReleaseBundlesSourceTests {

		@Test
		void createWhenReleaseBundlesIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundlesSource(null))
				.withMessage("'releaseBundles' must not be empty");
		}

		@Test
		void createWhenReleaseBundlesIsEmptyThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundlesSource(Collections.emptyList()))
				.withMessage("'releaseBundles' must not be empty");
		}

	}

	@Nested
	class ReleaseBundleSourceTests {

		@Test
		void createWhenReleaseBundleNameIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundleSource(null, "1.2.3", null, null))
				.withMessage("'releaseBundleName' must not be empty");
		}

		@Test
		void createWhenReleaseBundleVersionIsNullThrowsException() {
			assertThatIllegalArgumentException().isThrownBy(() -> new ReleaseBundleSource("name", null, null, null))
				.withMessage("'releaseBundleVersion' must not be empty");
		}

	}

}
