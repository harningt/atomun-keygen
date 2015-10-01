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

package us.eharning.atomun.keygen;

import com.google.common.collect.ImmutableList;
import us.eharning.atomun.keygen.base.ValidationException;
import us.eharning.atomun.keygen.internal.spi.bip0032.BIP0032KeyGeneratorServiceProvider;
import us.eharning.atomun.keygen.internal.spi.bip0032.BIP0044KeyGeneratorServiceProvider;
import us.eharning.atomun.keygen.spi.BuilderParameter;
import us.eharning.atomun.keygen.spi.KeyGeneratorBuilderSpi;
import us.eharning.atomun.keygen.spi.KeyGeneratorServiceProvider;

import java.util.Arrays;
import javax.annotation.Nonnull;

/**
 * Builder class to help simplify the process of setting up key generators.
 */
public class KeyGeneratorBuilder {
    private static final ImmutableList<KeyGeneratorServiceProvider> SERVICE_PROVIDERS = ImmutableList.of(
            new BIP0032KeyGeneratorServiceProvider(),
            new BIP0044KeyGeneratorServiceProvider()
    );

    /**
     * Implementation instance.
     */
    @Nonnull
    private final KeyGeneratorBuilderSpi spi;

    /* Current known number of parameters - internal detail.
     * Current slot dictates:
     *  1 - seed
     *  2 - path
     */
    private final BuilderParameter[] parameters = new BuilderParameter[2];

    private KeyGeneratorBuilder(@Nonnull KeyGeneratorBuilderSpi spi) {
        this.spi = spi;
    }

    /**
     * Create a new builder for the given algorithm.
     *
     * @param algorithm
     *         type of builder to return.
     *
     * @return a builder instance.
     */
    @Nonnull
    public static KeyGeneratorBuilder newBuilder(@Nonnull KeyGeneratorAlgorithm algorithm) {
        for (KeyGeneratorServiceProvider provider : SERVICE_PROVIDERS) {
            KeyGeneratorBuilderSpi spi = provider.getKeyGeneratorBuilder(algorithm);
            if (null != spi) {
                return new KeyGeneratorBuilder(spi);
            }
        }
        throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm);
    }

    /**
     * Build a key generator with the applied configuration.
     *
     * @return a key generator.
     */
    @Nonnull
    public DeterministicKeyGenerator build() throws ValidationException {
        try {
            spi.validate(parameters);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return spi.createGenerator(parameters);
    }

    /**
     * Set the seed for the key generator builder.
     *
     * @param seedParameter
     *         algorithmic base for the keys.
     *
     * @return self.
     */
    @Nonnull
    public KeyGeneratorBuilder setSeed(SeedParameter seedParameter) {
        this.parameters[0] = seedParameter;
        spi.validate(parameters);
        return this;
    }

    /**
     * Set the path used to derive the final builder from the base.
     *
     * @param pathParameter
     *         base path to use.
     *
     * @return self.
     */
    @Nonnull
    public KeyGeneratorBuilder setPath(PathParameter pathParameter) {
        this.parameters[1] = pathParameter;
        spi.validate(parameters);
        return this;
    }

    /**
     * Reset the builder to a clean state for clean re-use.
     *
     * @return self.
     */
    @Nonnull
    public KeyGeneratorBuilder reset() {
        Arrays.fill(parameters, null);
        return this;
    }
}
