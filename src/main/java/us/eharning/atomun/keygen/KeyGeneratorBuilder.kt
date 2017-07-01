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

import com.google.common.collect.ImmutableList
import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.keygen.internal.spi.bip0032.BIP0032KeyGeneratorServiceProvider
import us.eharning.atomun.keygen.internal.spi.bip0032.BIP0044KeyGeneratorServiceProvider
import us.eharning.atomun.keygen.spi.BuilderParameter
import us.eharning.atomun.keygen.spi.KeyGeneratorBuilderSpi
import java.util.*

/**
 * Builder class to help simplify the process of setting up key generators.
 */
class KeyGeneratorBuilder private constructor(
        private val spi: KeyGeneratorBuilderSpi
) {
    /* Current known number of parameters - internal detail.
     * Current slot dictates:
     *  1 - seed
     *  2 - path
     */
    private val parameters = arrayOfNulls<BuilderParameter>(2)

    /**
     * Build a key generator with the applied configuration.
     *
     * @return a key generator.
     */
    @Throws(ValidationException::class)
    fun build(): DeterministicKeyGenerator {
        try {
            spi.validate(*parameters)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        return spi.createGenerator(*parameters)
    }

    /**
     * Set the seed for the key generator builder.
     *
     * @param seedParameter
     *         algorithmic base for the keys.
     *
     * @return self.
     */
    fun setSeed(seedParameter: SeedParameter): KeyGeneratorBuilder {
        this.parameters[0] = seedParameter
        spi.validate(*parameters)
        return this
    }

    /**
     * Set the path used to derive the final builder from the base.
     *
     * @param pathParameter
     *         base path to use.
     *
     * @return self.
     */
    fun setPath(pathParameter: PathParameter): KeyGeneratorBuilder {
        this.parameters[1] = pathParameter
        spi.validate(*parameters)
        return this
    }

    /**
     * Reset the builder to a clean state for clean re-use.
     *
     * @return self.
     */
    fun reset(): KeyGeneratorBuilder {
        Arrays.fill(parameters, null)
        return this
    }

    companion object {
        private val SERVICE_PROVIDERS = ImmutableList.of(
                BIP0032KeyGeneratorServiceProvider(),
                BIP0044KeyGeneratorServiceProvider()
        )

        /**
         * Create a new builder for the given algorithm.
         * @param algorithm
         *         type of builder to return.
         *
         * @return a builder instance.
         */
        @JvmStatic
        fun newBuilder(algorithm: KeyGeneratorAlgorithm): KeyGeneratorBuilder {
            for (provider in SERVICE_PROVIDERS) {
                val spi = provider.getKeyGeneratorBuilder(algorithm)
                if (null != spi) {
                    return KeyGeneratorBuilder(spi)
                }
            }
            throw UnsupportedOperationException("Unsupported algorithm: " + algorithm)
        }
    }
}
