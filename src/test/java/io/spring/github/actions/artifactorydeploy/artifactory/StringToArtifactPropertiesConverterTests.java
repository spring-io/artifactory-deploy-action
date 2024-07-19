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

package io.spring.github.actions.artifactorydeploy.artifactory;

import java.util.List;

import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy.ArtifactProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link StringToArtifactPropertiesConverter}.
 *
 * @author Andy Wilkinson
 * @author Artem Bilan
 */
class StringToArtifactPropertiesConverterTests {

	private final StringToArtifactPropertiesConverter converter = new StringToArtifactPropertiesConverter();

	@Test
	void convertWithSingleLineProducesOneArtifactProperties() {
		List<ArtifactProperties> artifactProperties = this.converter.convert("one,two:three:a=alpha,b=bravo");
		assertThat(artifactProperties).hasSize(1).first().satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("one", "two");
			assertThat(properties.exclude()).containsExactly("three");
			assertThat(properties.properties()).hasSize(2).containsEntry("a", "alpha").containsEntry("b", "bravo");
		});
	}

	@Test
	void convertWithEmptyIncludeHasEmptyListInArtifactProperties() {
		List<ArtifactProperties> artifactProperties = this.converter.convert(":one,two:a=alpha");
		assertThat(artifactProperties).hasSize(1).first().satisfies((properties) -> {
			assertThat(properties.include()).isEmpty();
			assertThat(properties.exclude()).containsExactly("one", "two");
			assertThat(properties.properties()).hasSize(1).containsEntry("a", "alpha");
		});
	}

	@Test
	void convertWithEmptyExcludeHasEmptyListInArtifactProperties() {
		List<ArtifactProperties> artifactProperties = this.converter.convert("one,two::a=alpha");
		assertThat(artifactProperties).hasSize(1).first().satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("one", "two");
			assertThat(properties.exclude()).isEmpty();
			assertThat(properties.properties()).hasSize(1).containsEntry("a", "alpha");
		});
	}

	@Test
	void convertWithPropertyWithEqualsInValueHasProperty() {
		List<ArtifactProperties> artifactProperties = this.converter.convert("one:two:a=alpha=bravo");
		assertThat(artifactProperties).hasSize(1).first().satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("one");
			assertThat(properties.exclude()).containsExactly("two");
			assertThat(properties.properties()).hasSize(1).containsEntry("a", "alpha=bravo");
		});
	}

	@Test
	void convertWithMultipleLinesProducesMultipleArtifactProperties() {
		List<ArtifactProperties> artifactProperties = this.converter
			.convert("one,two:three:a=alpha,b=bravo%n    %nfour:five:c=charlie%nsix:seven:d=delta".formatted());
		assertThat(artifactProperties).hasSize(3).first().satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("one", "two");
			assertThat(properties.exclude()).containsExactly("three");
			assertThat(properties.properties()).hasSize(2).containsEntry("a", "alpha").containsEntry("b", "bravo");
		});
		assertThat(artifactProperties).element(1).satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("four");
			assertThat(properties.exclude()).containsExactly("five");
			assertThat(properties.properties()).hasSize(1).containsEntry("c", "charlie");
		});
		assertThat(artifactProperties).element(2).satisfies((properties) -> {
			assertThat(properties.include()).containsExactly("six");
			assertThat(properties.exclude()).containsExactly("seven");
			assertThat(properties.properties()).hasSize(1).containsEntry("d", "delta");
		});
	}

}
