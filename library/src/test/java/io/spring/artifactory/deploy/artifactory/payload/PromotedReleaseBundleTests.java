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

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link PromotedReleaseBundle}.
 *
 * @author Phillip Webb
 */
@JsonTest
@ActiveProfiles("test")
class PromotedReleaseBundleTests {

	@Autowired
	private JacksonTester<PromotedReleaseBundle> json;

	@Test
	void readDeserializesJson() throws Exception {
		assertThat(this.json.read("promoted-release-bundle.json")).satisfies((promotedReleaseBundle) -> {
			assertThat(promotedReleaseBundle.repositoryKey()).isEqualTo("release-bundles-v2");
			assertThat(promotedReleaseBundle.releaseBundleName()).isEqualTo("rasuli-test");
			assertThat(promotedReleaseBundle.releaseBundleVersion()).isEqualTo("2");
			assertThat(promotedReleaseBundle.environment()).isEqualTo("env");
			assertThat(promotedReleaseBundle.includedRepositoryKeys()).containsExactly("a", "b");
			assertThat(promotedReleaseBundle.excludedRepositoryKeys()).containsExactly("c", "d");
			assertThat(promotedReleaseBundle.created()).isNotNull();
			assertThat(promotedReleaseBundle.createdMillis()).isEqualTo(123);
			assertThat(promotedReleaseBundle.sourceEnvironment()).isEqualTo("se");
		});
	}

}
