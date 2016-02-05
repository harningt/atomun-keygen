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

import com.google.common.base.Objects;
import us.eharning.atomun.core.ValidationException;
import us.eharning.atomun.core.ec.ECKey;
import us.eharning.atomun.keygen.internal.HierarchicalKeyGenerator;

import javax.annotation.Nonnull;

/**
 * Key Generator following BIP32 https://en.bitcoin.it/wiki/BIP_0032
 */
final class BIP0032Generator implements HierarchicalKeyGenerator {
    static final BIP0032NodeProcessor strategy = new BouncyCastleBIP0032NodeProcessor();

    private final BIP0032Node node;

    /**
     * Construct a generator wrapping a given node value.
     *
     * @param node
     *         BIP0032 parameters to wrap.
     */
    BIP0032Generator(@Nonnull BIP0032Node node) {
        this.node = node;
    }

    /**
     * Obtain the public-key-only generator, omitting private key generation bits.
     *
     * @return key generator without private key generation capabilities.
     */
    @Override
    @Nonnull
    public BIP0032Generator getPublic() {
        /* If this is already public, return this */
        if (!node.getMaster().hasPrivate()) {
            return this;
        }
        return new BIP0032Generator(strategy.getPublic(node));
    }

    /**
     * Export the private/public bits of this key generator for later import dependent on what is available.
     * BIP0032 uses Base58+checksum format.
     *
     * @return exported key data in string form.
     */
    @Override
    @Nonnull
    public String export() {
        return strategy.exportNode(node);
    }

    /**
     * Export the public bits of this key generator for later import.
     * BIP0032 uses Base58+checksum format.
     *
     * @return exported public key in string form.
     */
    @Override
    @Nonnull
    public String exportPublic() {
        return strategy.exportNode(strategy.getPublic(node));
    }

    /**
     * Return whether or not this generator has private key generation bits.
     *
     * @return true if generator has private bits.
     */
    @Override
    public boolean hasPrivate() {
        return node.hasPrivate();
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
    @Override
    @Nonnull
    public ECKey generate(int sequence) throws ValidationException {
        return strategy.deriveNode(node, sequence).getMaster();
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
    @Override
    @Nonnull
    public ECKey generatePublic(int sequence) throws ValidationException {
        return strategy.deriveNode(node, sequence).getMaster().getPublic();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        BIP0032Generator that = (BIP0032Generator) obj;
        return Objects.equal(node, that.node);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(node);
    }

}
