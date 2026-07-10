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

/**
 * Release bunlde promotion information.
 *
 * @author Phillip Webb
 * @param stage the name of the target environment/stage for the promotion
 * @param includedRepositoryKeys the specific repositories to include in the promotion
 * @param excludedRepositoryKeys the specific repositories to exclude from the promotion
 * @param includedSourcePaths the specific source paths to include in the promotion
 * @param excludedSourcePaths specific source paths to exclude from the promotion
 * @param overwriteStrategy the strategy for overwriting artifacts when a promotion would
 * overwrite a file that is not part of the release bundle
 * @param artifactAdditionalProperties key-value pairs that define properties to add to
 * each promoted artifact on top of any existing properties
 * @param promotionAuthorizationType type of promotion authorization
 */
public record ReleaseBundlePromotion(String stage, List<String> includedRepositoryKeys,
		List<String> excludedRepositoryKeys, List<String> includedSourcePaths, List<String> excludedSourcePaths,
		OverwriteStrategy overwriteStrategy, Map<String, String> artifactAdditionalProperties,
		PromotionAuthorizationType promotionAuthorizationType) {

	/**
	 * Overwrite strategies.
	 */
	public enum OverwriteStrategy {

		/**
		 * overwrite the artifact only if the artifact has tag {@code latest}.
		 */
		LATEST,

		/**
		 * Overwrite all.
		 */
		ALL,

		/**
		 * Fail if an artifact can't be overwritten.
		 */
		DISABLED

	}

	/**
	 * Promotion authorization types.
	 */
	public enum PromotionAuthorizationType {

		/**
		 * Undefined authorization.
		 */
		UNDEFINED,

		/**
		 * App trust authorized promotion.
		 */
		APP_TRUST_AUTHORIZED_PROMOTION

	}

}
