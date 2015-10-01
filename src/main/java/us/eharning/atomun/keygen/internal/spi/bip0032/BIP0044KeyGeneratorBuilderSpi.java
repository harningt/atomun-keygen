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

package us.eharning.atomun.keygen.internal.spi.bip0032;

import com.google.common.base.Preconditions;
import us.eharning.atomun.keygen.ByteArraySeedParameter;
import us.eharning.atomun.keygen.DeterministicKeyGenerator;
import us.eharning.atomun.keygen.SeedParameter;
import us.eharning.atomun.keygen.SerializedSeedParameter;
import us.eharning.atomun.keygen.StandardKeyGeneratorAlgorithm;
import us.eharning.atomun.keygen.base.ValidationException;
import us.eharning.atomun.keygen.path.BIP0032Path;
import us.eharning.atomun.keygen.path.BIP0044Path;
import us.eharning.atomun.keygen.spi.BuilderParameter;
import us.eharning.atomun.keygen.spi.KeyGeneratorBuilderSpi;

import javax.annotation.Nonnull;

/**
 * Service provider for the BIP0044 key generator specification.
 */
final class BIP0044KeyGeneratorBuilderSpi extends KeyGeneratorBuilderSpi {
    /**
     * Construct a new SPI with the given algorithm.
     *
     * @since 0.0.1
     */
    protected BIP0044KeyGeneratorBuilderSpi() {
        super(StandardKeyGeneratorAlgorithm.BIP0044);
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
    @Override
    public DeterministicKeyGenerator createGenerator(BuilderParameter... parameters) throws ValidationException {
        BIP0032Node node = null;
        BIP0044Path path = null;
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof SeedParameter) {
                if (null != node) {
                    throw new IllegalArgumentException("Only one SeedParameter allowed per builder");
                }
                if (parameter instanceof SerializedSeedParameter) {
                    node = BIP0032Generator.strategy.importNode(((SerializedSeedParameter) parameter).getSerializedSeed());
                } else if (parameter instanceof ByteArraySeedParameter) {
                    node = BIP0032Generator.strategy.generateNodeFromSeed(((ByteArraySeedParameter) parameter).getSeed());
                } else {
                    throw new IllegalArgumentException("Unsupported SeedParameter type");
                }
            } else if (parameter instanceof BIP0032Path) {
                if (null != path) {
                    throw new IllegalArgumentException("Only one BIP0032Path allowed per builder");
                }
                if (!(parameter instanceof BIP0044Path)) {
                    path = BIP0044Path.fromPath((BIP0032Path) parameter);
                } else {
                    path = (BIP0044Path) parameter;
                }
                Preconditions.checkArgument(path.hasChain(), "Missing final required path element: Chain");
            } else {
                throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
            }
        }
        if (null == node) {
            node = BIP0032Generator.strategy.generateNode();
        }

        if (null == path) {
            throw new IllegalArgumentException("Missing path");
        }
        node = BIP0032Generator.strategy.deriveNode(node, path);

        return new BIP0032Generator(node);
    }

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
    @Override
    public void validate(BuilderParameter... parameters) {
        boolean foundSeed = false;
        boolean foundPath = false;
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof SeedParameter) {
                if (foundSeed) {
                    throw new IllegalArgumentException("Only one SeedParameter allowed per builder");
                }
                foundSeed = true;
                if (parameter instanceof ByteArraySeedParameter) {
                    /* Check length */
                } else if (parameter instanceof SerializedSeedParameter) {
                    /* Check format */
                } else {
                    throw new IllegalArgumentException("Unsupported SeedParameter type");
                }
            } else if (parameter instanceof BIP0032Path) {
                if (foundPath) {
                    throw new IllegalArgumentException("Only one BIP0032Path allowed per builder");
                }
                BIP0044Path.checkValidPath((BIP0032Path) parameter);
                foundPath = true;
            } else {
                throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
            }
        }
    }
}
