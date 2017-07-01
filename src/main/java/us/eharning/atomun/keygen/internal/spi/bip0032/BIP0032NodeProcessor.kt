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

package us.eharning.atomun.keygen.internal.spi.bip0032

import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.keygen.path.BIP0032Path

/**
 * Processor class to implement operations on BIP0032 node instances.
 */
internal interface BIP0032NodeProcessor {
    /**
     * Convert the node into a Base58+checksum encoded string.
     *
     * @param node
     *         instance to encode.
     *
     * @return Base58+checksum encoded string.
     */
    fun exportNode(node: BIP0032Node): String

    /**
     * Convert the Base58+checksum encoded string into a BIP0032 node.
     *
     * @param serialized
     *         encoded string to decode.
     *
     * @return BIP0032 node represented by the serialized string.
     *
     * @throws ValidationException
     *         if the data is not a valid encoded BIP0032 node.
     */
    @Throws(ValidationException::class)
    fun importNode(serialized: String): BIP0032Node

    /**
     * Generates a BIP0032 node from a seed value that is passed through a basic HMAC process.
     *
     * @param seed
     *         value for which the node should be generated.
     *
     * @return BIP0032 node deterministically based on the seed input.
     *
     * @throws ValidationException
     *         if either cryptography fails (unlikely)
     *         or the seed results in an invalid EC key (unlikely).
     */
    @Throws(ValidationException::class)
    fun generateNodeFromSeed(seed: ByteArray): BIP0032Node

    /**
     * Generates a random BIP0032 node.
     *
     * @return BIP0032 node randomly generated.
     */
    fun generateNode(): BIP0032Node

    /**
     * Derives a BIP0032 node given the input path.
     *
     * @param node
     *         base node to derive from.
     * @param path
     *         set of sequence values to use for derivation.
     *
     * @return BIP0032 node derived using the necessary algorithms per BIP0032 specification.
     *
     * @throws ValidationException
     *         if it is impossible to generate a key using the path,
     *         it is impossible to derive a key due to missing private bits,
     *         or the resultant key is an invalid EC key (unlikely).
     */
    @Throws(ValidationException::class)
    fun deriveNode(node: BIP0032Node, path: BIP0032Path): BIP0032Node

    /**
     * Derives a BIP0032 node given the singular sequence value.
     *
     * @param node
     *         base node to derive from.
     * @param sequence
     *         value to use for derivation.
     *
     * @return BIP0032 node derived using the necessary algorithms per BIP0032 specification.
     *
     * @throws ValidationException
     *         it is impossible to derive a key due to missing private bits,
     *         or the resultant key is an invalid EC key (unlikely).
     */
    @Throws(ValidationException::class)
    fun deriveNode(node: BIP0032Node, sequence: Int): BIP0032Node

    /**
     * Obtain the BIP0032 node without its private bits (if present).
     *
     * @param node
     *         instance to obtain a version of without private bits.
     *
     * @return BIP0032 node instance without private bits.
     */
    fun getPublic(node: BIP0032Node): BIP0032Node
}
