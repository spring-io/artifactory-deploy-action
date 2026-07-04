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

package io.spring.artifactory.deploy.artifactory.payload;

import java.io.File;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * {@link DeployableArtifact} backed by a {@link File}.
 *
 * @author Phillip Webb
 * @author Madhura Bhave
 */
public class DeployableFileArtifact implements DeployableArtifact {

	private final String path;

	private final Map<String, String> properties;

	private Checksums checksums;

	private final File file;

	/**
	 * Creates a new {@link DeployableFileArtifact}.
	 * @param path the deployment path
	 * @param file the file to deploy
	 * @param properties properties to attach to the artifact
	 * @param checksums pre-computed checksums, or {@code null} to compute on demand
	 */
	public DeployableFileArtifact(String path, File file, Map<String, String> properties, Checksums checksums) {
		Assert.notNull(file, "'file' must not be null");
		Assert.isTrue(file.exists(), "'file' '" + file + "' does not exist");
		Assert.isTrue(file.isFile(), "'file' '" + file + "' does not refer to a file");
		this.path = path;
		this.properties = (properties != null) ? Collections.unmodifiableMap(new LinkedHashMap<>(properties))
				: Collections.emptyMap();
		this.checksums = checksums;
		this.file = file;
	}

	@Override
	public String getPath() {
		return this.path;
	}

	@Override
	public Map<String, String> getProperties() {
		return this.properties;
	}

	@Override
	public Checksums getChecksums() {
		if (this.checksums == null) {
			this.checksums = Checksums.calculate(getContent());
		}
		return this.checksums;
	}

	@Override
	public Resource getContent() {
		return new FileSystemResource(this.file);
	}

	@Override
	public long getSize() {
		return this.file.length();
	}

	/**
	 * Calculates the deployment path of a file relative to a root directory.
	 * @param root the root directory
	 * @param file the file within the root directory
	 * @return the path of the file relative to the root, starting with {@code /}
	 */
	public static String calculatePath(File root, File file) {
		Assert.notNull(root, "'root' must not be null");
		Assert.notNull(file, "'file' must not be null");
		String rootPath = root.getAbsolutePath();
		String filePath = file.getAbsolutePath();
		Assert.isTrue(filePath.startsWith(rootPath), "File '" + root + "' is not a parent of '" + file + "'");
		return cleanPath(filePath.substring(rootPath.length() + 1));
	}

	private static String cleanPath(String path) {
		path = StringUtils.cleanPath(path);
		path = (path.startsWith("/") ? path : "/" + path);
		return path;
	}

}
