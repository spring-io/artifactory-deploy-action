/*
 * Copyright 2017-present the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundleDistribution.DistributionRule;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundleDistribution.Mapping;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundleDistribution.Modifications;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ReleaseBundleDistribution}.
 *
 * @author Phillip Webb
 */
@JsonTest
@ActiveProfiles("test")
class ReleaseBundleDistributionTests {

	@Autowired
	private JacksonTester<ReleaseBundleDistribution> json;

	@Test
	void writeSerializesJson() throws Exception {
		List<DistributionRule> distributionRules = new ArrayList<>();
		distributionRules.add(new DistributionRule("site", "city", List.of("USA")));
		Modifications modifications = new Modifications(true, List.of(new Mapping("in", "out")));
		ReleaseBundleDistribution distribution = new ReleaseBundleDistribution(true, distributionRules, modifications);
		assertThat(this.json.write(distribution)).isEqualToJson("release-bundle-distribution.json");
	}

}
