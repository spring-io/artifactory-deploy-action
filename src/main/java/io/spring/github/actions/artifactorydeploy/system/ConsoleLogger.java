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

package io.spring.github.actions.artifactorydeploy.system;

import org.slf4j.helpers.MessageFormatter;

/**
 * Simple console logger used to output progress messages.
 *
 * @author Andy Wilkinson
 */
public class ConsoleLogger {

	private final boolean debugEnabled;

	public ConsoleLogger() {
		this.debugEnabled = Boolean.valueOf(System.getenv("ACTIONS_STEP_DEBUG"));
	}

	public void log(String message, Object... args) {
		System.out.println(MessageFormatter.arrayFormat(message, args).getMessage());
	}

	public void debug(String message, Object... args) {
		if (this.debugEnabled) {
			log("##[debug]" + message, args);
		}
	}

}
