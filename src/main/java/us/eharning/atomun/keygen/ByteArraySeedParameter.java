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

import java.util.Arrays;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Seed parameter wrapping a byte array as the precise seed.
 */
@Immutable
public class ByteArraySeedParameter implements SeedParameter {
    @Nonnull
    private final byte[] seed;

    /**
     * Construct a new seed parameter from the given seed.
     *
     * @param seed
     *         byte array to copy as the seed.
     */
    private ByteArraySeedParameter(@Nonnull byte[] seed) {
        this.seed = Arrays.copyOf(seed, seed.length);
    }

    /**
     * Construct a new seed parameter from the given seed.
     *
     * @param seed
     *         byte array to copy as the seed.
     */
    public static ByteArraySeedParameter getParameter(@Nonnull byte[] seed) {
        return new ByteArraySeedParameter(seed);
    }

    /**
     * Obtain a copy of the seed byte array.
     *
     * @return copy of the seed byte array.
     */
    @Nonnull
    public byte[] getSeed() {
        return Arrays.copyOf(seed, seed.length);
    }
}
