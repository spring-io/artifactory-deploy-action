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

package io.spring.artifactory.deploy.system;

/**
 * Simple debug logger that outputs messages to the console when enabled.
 *
 * @author Andy Wilkinson
 */
public class DebugLogger {

	private static final ConsoleLogger console = new ConsoleLogger();

	private final boolean enabled;

	/**
	 * Creates a new {@link DebugLogger}, enabling output when the
	 * {@code ACTION_STEP_DEBUG} environment variable is set to {@code true}.
	 */
	public DebugLogger() {
		this.enabled = Boolean.parseBoolean(System.getenv("ACTION_STEP_DEBUG"));
	}

	/**
	 * Logs a message when debug mode is enabled.
	 * @param message the message, with SLF4J-style {@code {}} placeholders
	 * @param args arguments to substitute into the message
	 */
	public void log(String message, Object... args) {
		if (this.enabled) {
			console.log(message, args);
		}
	}

	/**
	 * Logs a debug message when debug mode is enabled.
	 * @param message the message, with SLF4J-style {@code {}} placeholders
	 * @param args arguments to substitute into the message
	 */
	public void debug(String message, Object... args) {
		if (this.enabled) {
			console.log(message, args);
		}
	}

}
