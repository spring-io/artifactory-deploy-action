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
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import io.spring.github.actions.artifactorydeploy.artifactory.payload.Checksums;
import io.spring.github.actions.artifactorydeploy.artifactory.payload.DeployableArtifact;
import io.spring.github.actions.artifactorydeploy.io.FileSet.Category;
import io.spring.github.actions.artifactorydeploy.openpgp.ArmoredAsciiSigner;
import io.spring.github.actions.artifactorydeploy.system.ConsoleLogger;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Utility to sign a set of batched {@link DeployableArtifact DeployableArtifacts}.
 *
 * @author Phillip Webb
 * @author Andy Wilkinson
 */
class DeployableArtifactsSigner {

	private static final String FILE_EXTENSION = ".asc";

	private static final ConsoleLogger console = new ConsoleLogger();

	private static final File temp;

	private final Map<String, String> buildProperties;

	static {
		try {
			temp = Files.createTempDirectory("artifactory-resource-asc").toFile();
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private final ArmoredAsciiSigner signer;

	DeployableArtifactsSigner(ArmoredAsciiSigner signer, Map<String, String> buildProperties) {
		this.signer = signer;
		this.buildProperties = buildProperties;
	}

	MultiValueMap<Category, DeployableArtifact> addSignatures(
			MultiValueMap<Category, DeployableArtifact> batchedArtifacts) {
		Assert.state(CollectionUtils.isEmpty(batchedArtifacts.get(Category.SIGNATURE)),
				"Files must not already be signed");
		List<DeployableArtifact> signed = batchedArtifacts.values()
			.stream()
			.flatMap(List::stream)
			.map(ArtifactSignature::new)
			.collect(Collectors.toList());
		LinkedMultiValueMap<Category, DeployableArtifact> batchedAndSigned = new LinkedMultiValueMap<>(
				batchedArtifacts);
		batchedAndSigned.put(Category.SIGNATURE, signed);
		return batchedAndSigned;
	}

	static boolean isSignatureFile(String name) {
		return name.toLowerCase().endsWith(FILE_EXTENSION);
	}

	private class ArtifactSignature implements DeployableArtifact {

		private final String path;

		private final FileSystemResource signatureResource;

		private final long size;

		private Checksums checksums;

		ArtifactSignature(DeployableArtifact artifact) {
			try {
				this.path = artifact.getPath() + FILE_EXTENSION;
				File signatureFile = new File(temp, artifact.getPath());
				this.signatureResource = new FileSystemResource(signatureFile);
				signatureFile.getParentFile().mkdirs();
				signatureFile.deleteOnExit();
				console.debug("Signing {}", artifact.getPath());
				DeployableArtifactsSigner.this.signer.sign(artifact.getContent().getInputStream(),
						this.signatureResource.getOutputStream());
				this.size = this.signatureResource.contentLength();
				this.checksums = Checksums.calculate(this.signatureResource);
			}
			catch (IOException ex) {
				throw new IllegalStateException(ex);
			}
		}

		@Override
		public String getPath() {
			return this.path;
		}

		@Override
		public Resource getContent() {
			return this.signatureResource;
		}

		@Override
		public long getSize() {
			return this.size;
		}

		@Override
		public Map<String, String> getProperties() {
			return DeployableArtifactsSigner.this.buildProperties;
		}

		@Override
		public Checksums getChecksums() {
			return this.checksums;
		}

	}

}
