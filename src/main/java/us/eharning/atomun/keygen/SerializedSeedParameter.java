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

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Seed parameter wrapping the serialized form of the given key generator.
 */
@Immutable
public class SerializedSeedParameter implements SeedParameter {
    @Nonnull
    private final String serialized;

    /**
     * Construct a new seed parameter from the given serialized form.
     *
     * @param serialized
     *         string to use for initializing the generator.
     */
    private SerializedSeedParameter(@Nonnull  String serialized) {
        this.serialized = serialized;
    }

    /**
     * Construct a new seed parameter from the given serialized form.
     *
     * @param serialized
     *         string to use for initializing the generator.
     */
    public static SerializedSeedParameter getParameter(@Nonnull  String serialized) {
        return new SerializedSeedParameter(serialized);
    }

    /**
     * Get the serialized string form of the key generator.
     *
     * @return the serialized string to use for initializing the generator.
     */
    @Nonnull
    public String getSerializedSeed() {
        return serialized;
    }
}
