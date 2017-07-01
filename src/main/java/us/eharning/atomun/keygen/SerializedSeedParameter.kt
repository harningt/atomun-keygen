/*
 * Copyright 2015, 2017 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package us.eharning.atomun.keygen

import javax.annotation.concurrent.Immutable

/**
 * Seed parameter wrapping the serialized form of the given key generator.
 */
@Immutable
class SerializedSeedParameter
/**
 * Construct a new seed parameter from the given serialized form.
 *
 * @param serializedSeed
 *         string to use for initializing the generator.
 */
private constructor(
        val serializedSeed: String
) : SeedParameter {

    companion object {
        /**
         * Construct a new seed parameter from the given serialized form.
         *
         * @param serialized
         *         string to use for initializing the generator.
         */
        @JvmStatic
        fun getParameter(serialized: String): SerializedSeedParameter {
            return SerializedSeedParameter(serialized)
        }
    }
}
