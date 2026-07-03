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

package io.spring.artifactory.deploy.system;

/**
 * Logger interface used by the library.
 *
 * @author Andy Wilkinson
 * @author Phillip Webb
 */
public interface Logger {

	/**
	 * Logs a message to standard output.
	 * @param message the message, with SLF4J-style {@code {}} placeholders
	 * @param args arguments to substitute into the message
	 */
	void log(String message, Object... args);

	/**
	 * Logs a debug message to standard output when debug mode is enabled.
	 * @param message the message, with SLF4J-style {@code {}} placeholders
	 * @param args arguments to substitute into the message
	 */
	void debug(String message, Object... args);

	/**
	 * Return a logger that outputs messages directly to the console.
	 * @param debug if debugging is enabled
	 * @return the logger
	 */
	static Logger console(boolean debug) {
		return new ConsoleLogger(debug);
	}

}
