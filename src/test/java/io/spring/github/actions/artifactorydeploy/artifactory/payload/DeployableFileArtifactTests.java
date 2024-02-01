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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.util.FileCopyUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DeployableFileArtifact}.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 * @author Andy Wilkinson
 */
class DeployableFileArtifactTests {

	private static final byte[] CONTENT = "abc".getBytes();

	@TempDir
	File tempDir;

	@Test
	void createWhenPropertiesIsNullUsesEmptyProperties() {
		DeployableArtifact artifact = create("/foo", CONTENT, null, null);
		assertThat(artifact.getProperties()).isNotNull().isEmpty();
	}

	@Test
	void createWhenChecksumIsNullCalculatesChecksums() {
		DeployableArtifact artifact = create("/foo", CONTENT, null, null);
		assertThat(artifact.getChecksums().getSha1()).isEqualTo("a9993e364706816aba3e25717850c26c9cd0d89d");
		assertThat(artifact.getChecksums().getMd5()).isEqualTo("900150983cd24fb0d6963f7d28e17f72");
	}

	@Test
	void getPropertiesReturnsProperties() {
		Map<String, String> properties = Collections.singletonMap("foo", "bar");
		DeployableArtifact artifact = create("/foo", CONTENT, properties, null);
		assertThat(artifact.getProperties()).isEqualTo(properties);
	}

	@Test
	void getChecksumReturnsChecksum() {
		Checksums checksums = new Checksums("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		DeployableArtifact artifact = create("/foo", CONTENT, null, checksums);
		assertThat(artifact.getChecksums()).isEqualTo(checksums);
	}

	@Test
	void getPathReturnsPath() {
		DeployableArtifact artifact = create("/foo/bar", CONTENT, null, null);
		assertThat(artifact.getPath()).isEqualTo("/foo/bar");
	}

	@Test
	void getContentReturnsContent() throws Exception {
		DeployableArtifact artifact = create("/foo", CONTENT, null, null);
		assertThat(FileCopyUtils.copyToByteArray(artifact.getContent().getInputStream())).isEqualTo(CONTENT);
	}

	private DeployableArtifact create(String path, byte[] content, Map<String, String> properties,
			Checksums checksums) {
		File artifact = new File(this.tempDir, path);
		artifact.getParentFile().mkdirs();
		try {
			Files.write(artifact.toPath(), content);
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		return new DeployableFileArtifact(path, artifact, properties, checksums);
	}

}
