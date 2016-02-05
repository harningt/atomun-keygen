/*
 * Copyright 2015 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.keygen.spi;

import com.google.common.annotations.Beta;
import com.google.common.base.Preconditions;
import us.eharning.atomun.core.ValidationException;
import us.eharning.atomun.keygen.DeterministicKeyGenerator;
import us.eharning.atomun.keygen.KeyGeneratorAlgorithm;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Key generator builder SPI concentrating on being a static instance that
 * offers up sanity-checks and enhanced APIs as necessary.
 *
 * @since 0.0.1
 */
@Beta
@Immutable
public abstract class KeyGeneratorBuilderSpi {
    private final KeyGeneratorAlgorithm algorithm;

    /**
     * Construct a new SPI with the given algorithm.
     *
     * @param algorithm
     *         implemented mnemonic algorithm.
     *
     * @since 0.0.1
     */
    protected KeyGeneratorBuilderSpi(@Nonnull KeyGeneratorAlgorithm algorithm) {
        Preconditions.checkNotNull(algorithm);
        this.algorithm = algorithm;
    }

    /**
     * Get the implemented key generation algorithm.
     *
     * @return implemented key generation algorithm.
     *
     * @since 0.0.1
     */
    @Nonnull
    public KeyGeneratorAlgorithm getAlgorithm() {
        return algorithm;
    }

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
    @Nonnull
    public abstract DeterministicKeyGenerator createGenerator(BuilderParameter... parameters) throws ValidationException;

    /**
     * Validate the builder parameters.
     *
     * @param parameters
     *         builder parameters to validate.
     *
     * @throws RuntimeException
     *         varieties in case of invalid input.
     * @since 0.0.1
     */
    public abstract void validate(BuilderParameter... parameters);
}
