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
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link Promotion}.
 *
 * @author Phillip Webb
 */
@JsonTest
@ActiveProfiles("test")
class PromotionTests {

	private static final Instant STARTED = ZonedDateTime
		.parse("2014-09-30T12:00:19.893123Z", DateTimeFormatter.ISO_DATE_TIME)
		.toInstant();

	@Autowired
	private JacksonTester<Promotion> json;

	@Test
	void writeSerializesJson() throws Exception {
		Promotion promotion = new Promotion("status", "comment", "user", STARTED, true, "from", "to", true, true, false,
				Set.of("s1", "s2"));
		assertThat(this.json.write(promotion)).isEqualToJson("promotion.json");
	}

}
