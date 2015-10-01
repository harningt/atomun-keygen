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

package us.eharning.atomun.keygen.base;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Base Elliptical Cryptography keypair interface.
 * <p>
 * Likely to change in the future and be pushed to a common library.
 * </p>
 */
@Immutable
public interface ECKey {
    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key or null if not present.
     */
    @CheckForNull
    byte[] exportPrivate();

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return true if the private key is present.
     */
    boolean hasPrivate();

    /**
     * Export the public key in ASN.1-encoded form.
     *
     * @return ASN.1 encoded public key bytes.
     */
    @Nonnull
    byte[] exportPublic();

    /**
     * Obtain the 'address hash' per Bitcoin rules.
     *
     * @return 20-byte address hash byte array
     */
    @Nonnull
    byte[] getAddressHash();

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    @Nonnull
    ECKey getPublic();

    /**
     * Perform an ECDSA signature using the private key.
     *
     * @param hash
     *         byte array to sign.
     *
     * @return ASN.1 representation of the signature.
     */
    @Nonnull
    byte[] sign(@Nonnull byte[] hash);

    /**
     * Verify an ECDSA signature using the public key.
     *
     * @param hash
     *         byte array of the hash to verify.
     * @param signature
     *         ASN.1 representation of the signature to verify hash with.
     *
     * @return true if the signature matches, else false.
     */
    boolean verify(@Nonnull byte[] hash, @Nonnull byte[] signature);
}