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

import okio.ByteString
import okio.ByteStrings
import javax.annotation.concurrent.Immutable

/**
 * Seed parameter wrapping a byte array as the precise seed.
 */
@Immutable
class ByteArraySeedParameter
/**
 * Construct a new seed parameter from the given seed.
 *
 * @param seed
 *         byte array to copy as the seed.
 */
private constructor(
        val seed: ByteString
) : SeedParameter {

    companion object {

        /**
         * Construct a new seed parameter from the given seed.
         *
         * @param seed
         *         byte array to copy as the seed.
         */
        @JvmStatic
        fun getParameter(seed: ByteArray): ByteArraySeedParameter {
            return getParameter(ByteString.of(*seed))
        }

        /**
         * Construct a new seed parameter from the given seed.
         *
         * @param seed
         *         byte string to set as seed.
         */
        @JvmStatic
        fun getParameter(seed: ByteString): ByteArraySeedParameter {
            return ByteArraySeedParameter(seed)
        }
    }
}
