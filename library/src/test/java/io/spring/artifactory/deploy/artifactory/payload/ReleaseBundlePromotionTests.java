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

import java.util.List;
import java.util.Map;

import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundlePromotion.OverwriteStrategy;
import io.spring.artifactory.deploy.artifactory.payload.ReleaseBundlePromotion.PromotionAuthorizationType;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ReleaseBundlePromotion}.
 *
 * @author Phillip Webb
 */
@JsonTest
@ActiveProfiles("test")
class ReleaseBundlePromotionTests {

	@Autowired
	private JacksonTester<ReleaseBundlePromotion> json;

	@Test
	void writeSerializesJson() throws Exception {
		ReleaseBundlePromotion promotion = new ReleaseBundlePromotion("st", List.of("a", "b"), List.of("c", "d"),
				List.of("e"), List.of("f"), OverwriteStrategy.LATEST, Map.of("foo", "bar"),
				PromotionAuthorizationType.APP_TRUST_AUTHORIZED_PROMOTION);
		assertThat(this.json.write(promotion)).isEqualToJson("release-bundle-promotion.json");
	}

}
