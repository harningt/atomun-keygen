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
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.keygen.internal.HierarchicalKeyGenerator

/**
 * Key Generator following BIP32 https://en.bitcoin.it/wiki/BIP_0032
 */
internal data class BIP0032Generator
/**
 * Construct a generator wrapping a given node value.
 *
 * @param node
 *         BIP0032 parameters to wrap.
 */
(
        private val node: BIP0032Node
) : HierarchicalKeyGenerator {

    /**
     * Obtain the public-key-only generator, omitting private key generation bits.
     *
     * @return key generator without private key generation capabilities.
     */
    override val public: BIP0032Generator
        get() {
            if (!node.master.hasPrivate()) {
                return this
            }
            return BIP0032Generator(strategy.getPublic(node))
        }

    /**
     * Export the private/public bits of this key generator for later import dependent on what is available.
     * BIP0032 uses Base58+checksum format.
     *
     * @return exported key data in string form.
     */
    override fun export(): String {
        return strategy.exportNode(node)
    }

    /**
     * Export the public bits of this key generator for later import.
     * BIP0032 uses Base58+checksum format.
     *
     * @return exported public key in string form.
     */
    override fun exportPublic(): String {
        return strategy.exportNode(strategy.getPublic(node))
    }

    /**
     * Return whether or not this generator has private key generation bits.
     *
     * @return true if generator has private bits.
     */
    override fun hasPrivate(): Boolean {
        return node.hasPrivate()
    }

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
    override fun generate(sequence: Int): ECKey {
        return strategy.deriveNode(node, sequence).master
    }

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
    override fun generatePublic(sequence: Int): ECKey {
        return strategy.deriveNode(node, sequence).master.public
    }

    companion object {
        val strategy: BIP0032NodeProcessor = BouncyCastleBIP0032NodeProcessor()
    }
}
