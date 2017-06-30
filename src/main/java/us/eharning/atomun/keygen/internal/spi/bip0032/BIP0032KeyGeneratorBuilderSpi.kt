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
import us.eharning.atomun.keygen.ByteArraySeedParameter
import us.eharning.atomun.keygen.DeterministicKeyGenerator
import us.eharning.atomun.keygen.SeedParameter
import us.eharning.atomun.keygen.SerializedSeedParameter
import us.eharning.atomun.keygen.StandardKeyGeneratorAlgorithm
import us.eharning.atomun.keygen.path.BIP0032Path
import us.eharning.atomun.keygen.spi.BuilderParameter
import us.eharning.atomun.keygen.spi.KeyGeneratorBuilderSpi

/**
 * Service provider for the BIP0032 key generator specification.
 *
 * @since 0.0.1
 */
internal class BIP0032KeyGeneratorBuilderSpi : KeyGeneratorBuilderSpi(StandardKeyGeneratorAlgorithm.BIP0032) {

    /**
     * Construct a key generator.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return DeterministicKeyGenerator instance wrapping build results.
     *
     * @since 0.0.1
     */
    @Throws(ValidationException::class)
    override fun createGenerator(vararg parameters: BuilderParameter?): DeterministicKeyGenerator {
        var node: BIP0032Node? = null
        var path: BIP0032Path? = null
        for (parameter in parameters) {
            if (null == parameter) {
                continue
            }
            /* Check counts */
            when (parameter) {
                is SeedParameter -> {
                    require(null == node, { "Only one SeedParameter allowed per builder" })
                }
                is BIP0032Path -> {
                    require(null == path, { "Only one BIP0032Path allowed per builder" })
                }
                else -> throw IllegalArgumentException("Unsupported parameter type: " + parameter)
            }
            when (parameter) {
                is SerializedSeedParameter ->
                    node = BIP0032Generator.strategy.importNode(parameter.serializedSeed)
                is ByteArraySeedParameter ->
                    node = BIP0032Generator.strategy.generateNodeFromSeed(parameter.getSeed())
                is BIP0032Path ->
                    path = parameter
                else -> throw IllegalArgumentException("Unsupported parameter type: " + parameter)
            }
        }
        if (null == node) {
            node = BIP0032Generator.strategy.generateNode()
        }

        if (null != path) {
            node = BIP0032Generator.strategy.deriveNode(node, path)
        }
        return BIP0032Generator(node)
    }

    /**
     * Validate the builder parameters.
     *
     * @param parameters
     *         builder parameters to validate.
     *
     * @throws RuntimeException
     *         varieties in case of invalid input.
     *
     * @since 0.0.1
     */
    override fun validate(vararg parameters: BuilderParameter?) {
        var foundSeed = false
        var foundPath = false
        for (parameter in parameters) {
            if (null == parameter) {
                continue
            }
            /* Check counts */
            when (parameter) {
                is SeedParameter -> {
                    require(!foundSeed, { "Only one SeedParameter allowed per builder" })
                    foundSeed = true
                }
                is BIP0032Path -> {
                    require(!foundPath, { "Only one BIP0032Path allowed per builder" })
                    foundPath = true
                }
                else -> throw IllegalArgumentException("Unsupported parameter type: " + parameter)
            }
            /* Check types */
            when (parameter) {
                is ByteArraySeedParameter,
                is SerializedSeedParameter,
                is BIP0032Path -> {}
                else -> throw IllegalArgumentException("Unsupported parameter type: " + parameter)
            }
        }
    }
}
