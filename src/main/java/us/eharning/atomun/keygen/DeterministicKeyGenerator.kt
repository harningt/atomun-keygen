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

import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.core.ec.ECKey

/**
 * Generator of deterministic EC keys.
 */
interface DeterministicKeyGenerator {
    /**
     * Return whether or not this generator has private key generation bits.
     *
     * @return true if generator has private bits.
     */
    fun hasPrivate(): Boolean

    /**
     * Generate a private key for the given sequence.
     *
     * @param sequence
     *         integer representing the key to generate.
     *
     * @return generated private key.
     *
     * @throws ValidationException
     *         if no private key is available or if somehow an invalid key is generated.
     */
    @Throws(ValidationException::class)
    fun generate(sequence: Int): ECKey

    /**
     * Generate a public key for the given sequence.
     *
     * @param sequence
     *         integer representing the key to generate.
     *
     * @return generated public key.
     *
     * @throws ValidationException
     *         if somehow an invalid key is generated.
     */
    @Throws(ValidationException::class)
    fun generatePublic(sequence: Int): ECKey

    /**
     * Export the private/public bits of this key generator for later import dependent on what is available.
     *
     * @return exported key data in string form.
     */
    fun export(): String

    /**
     * Export the public bits of this key generator for later import.
     *
     * @return exported public key in string form.
     */
    fun exportPublic(): String
}
