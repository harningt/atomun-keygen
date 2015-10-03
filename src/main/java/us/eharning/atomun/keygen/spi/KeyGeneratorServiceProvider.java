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

import us.eharning.atomun.keygen.KeyGeneratorAlgorithm;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

/**
 * Common service implementation for key generators.
 *
 * @since 0.0.1
 */
public abstract class KeyGeneratorServiceProvider {
    /**
     * Obtain a key generator builder SPI for the given algorithm.
     *
     * @param algorithm
     *         mnemonic algorithm to try to retrieve.
     *
     * @return SPI instance for the given algorithm, else null.
     *
     * @since 0.0.1
     */
    @CheckForNull
    public abstract KeyGeneratorBuilderSpi getKeyGeneratorBuilder(@Nonnull KeyGeneratorAlgorithm algorithm);

}