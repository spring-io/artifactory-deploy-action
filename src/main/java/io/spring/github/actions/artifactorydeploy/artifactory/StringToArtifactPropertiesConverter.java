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

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.spring.github.actions.artifactorydeploy.ArtifactoryDeployProperties.Deploy.ArtifactProperties;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Converter to create a list of {@link ArtifactProperties artifact properties} from a
 * {@link String}.
 *
 * @author Andy Wilkinson
 */
class StringToArtifactPropertiesConverter implements Converter<String, List<ArtifactProperties>> {

	@Override
	public List<ArtifactProperties> convert(String source) {
		BufferedReader reader = new BufferedReader(new StringReader(source));
		return reader.lines().map(this::toArtifactProperties).filter(Objects::nonNull).toList();
	}

	private ArtifactProperties toArtifactProperties(String line) {
		if (!StringUtils.hasLength(line)) {
			return null;
		}
		String[] components = line.split(":");
		Assert.state(components != null && components.length == 3,
				"Artifact properties must be configured in the form <includes>:<excludes>:<properties>");
		return new ArtifactProperties(commaSeparatedList(components[0]), commaSeparatedList(components[1]),
				commaSeparatedKeyValues(components[2]));
	}

	private List<String> commaSeparatedList(String input) {
		if (!StringUtils.hasText(input)) {
			return Collections.emptyList();
		}
		return Arrays.asList(input.split(","));
	}

	private Map<String, String> commaSeparatedKeyValues(String input) {
		Map<String, String> properties = new LinkedHashMap<>();
		for (String pair : input.split(",")) {
			int equalsIndex = pair.indexOf('=');
			String key = pair.substring(0, equalsIndex);
			String value = pair.substring(equalsIndex + 1, pair.length());
			properties.put(key, value);
		}
		return properties;
	}

}
