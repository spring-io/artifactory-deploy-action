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

/**
 * Simple debug logger that outputs messages to the console when enabled.
 *
 * @author Andy Wilkinson
 */
public class DebugLogger {

	private static final ConsoleLogger console = new ConsoleLogger();

	private final boolean enabled;

	public DebugLogger() {
		this.enabled = Boolean.valueOf(System.getenv("ACTION_STEP_DEBUG"));
	}

	public void log(String message, Object... args) {
		if (this.enabled) {
			console.log(message, args);
		}
	}

	public void debug(String message, Object... args) {
		if (this.enabled) {
			console.log(message, args);
		}
	}

}
