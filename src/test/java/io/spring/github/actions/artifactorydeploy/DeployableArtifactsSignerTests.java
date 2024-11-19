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

package io.spring.github.actions.artifactorydeploy;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableFileArtifact;
import io.spring.github.actions.artifactorydeploy.io.FileSet.Category;
import io.spring.github.actions.artifactorydeploy.openpgp.ArmoredAsciiSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.util.FileCopyUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link DeployableArtifactsSigner}.
 *
 * @author Phillip Webb
 * @author Andy Wilkinson
 */
class DeployableArtifactsSignerTests {

	private final Map<String, String> properties = Map.of("test", "param");

	@TempDir
	File tempDir;

	private DeployableArtifactsSigner signer;

	@BeforeEach
	void setup() throws IOException {
		String signingKey = new String(ArmoredAsciiSigner.class.getResourceAsStream("test-private.txt").readAllBytes(),
				StandardCharsets.UTF_8);
		ArmoredAsciiSigner signer = ArmoredAsciiSigner.get(signingKey, "password", null);
		this.signer = new DeployableArtifactsSigner(signer, this.properties);
	}

	@Test
	void signWhenAlreadyContainsSignedFilesThrowsException() {
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = new LinkedMultiValueMap<>();
		batchedArtifacts.add(Category.SIGNATURE, artifact("/file.asc", new byte[0]));
		assertThatIllegalStateException().isThrownBy(() -> this.signer.addSignatures(batchedArtifacts))
			.withMessage("Files must not already be signed");
	}

	@Test
	void signAddsSignedFiles() throws Exception {
		DeployableArtifact artifact = artifact("/com/example/myapp.jar", "test".getBytes(StandardCharsets.UTF_8));
		MultiValueMap<Category, DeployableArtifact> batchedArtifacts = new LinkedMultiValueMap<>();
		batchedArtifacts.add(Category.PRIMARY, artifact);
		MultiValueMap<Category, DeployableArtifact> signed = this.signer.addSignatures(batchedArtifacts);
		assertThat(signed.getFirst(Category.PRIMARY)).isEqualTo(artifact);
		DeployableArtifact signatureResource = signed.getFirst(Category.SIGNATURE);
		assertThat(signatureResource.getPath()).isEqualTo("/com/example/myapp.jar.asc");
		assertThat(FileCopyUtils.copyToByteArray(signatureResource.getContent().getInputStream()))
			.asString(StandardCharsets.UTF_8)
			.contains("PGP SIGNATURE");
		assertThat(signatureResource.getSize()).isGreaterThan(10);
		assertThat(signatureResource.getProperties()).isEqualTo(this.properties);
		assertThat(signatureResource.getChecksums()).isNotNull();
	}

	private DeployableArtifact artifact(String path, byte[] bytes) {
		File artifact = new File(this.tempDir, path);
		artifact.getParentFile().mkdirs();
		try {
			Files.write(artifact.toPath(), bytes);
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		return new DeployableFileArtifact(path, artifact, null, null);
	}

}
