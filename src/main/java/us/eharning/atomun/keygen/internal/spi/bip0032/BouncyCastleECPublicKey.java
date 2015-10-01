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
import com.google.common.base.Preconditions;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import us.eharning.atomun.keygen.base.ECKey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * ECKey implementation wrapping a public key using BouncyCastle.
 */
@Immutable
class BouncyCastleECPublicKey implements ECKey {
    protected static final SecureRandom secureRandom = new SecureRandom();
    protected static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    protected static final ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

    @Nonnull
    protected final byte[] encodedPublicKey;
    protected final boolean compressed;

    /**
     * Construct a public key from the given encoded public key and whether or not to treat is as compressed.
     *
     * @param encodedPublicKey
     *         DER-encoded EC public key.
     * @param compressed
     *         whether or not the EC public key is in compressed point form.
     */
    public BouncyCastleECPublicKey(@Nonnull byte[] encodedPublicKey, boolean compressed) {
        Preconditions.checkNotNull(encodedPublicKey);
        this.encodedPublicKey = Arrays.copyOf(encodedPublicKey, encodedPublicKey.length);
        this.compressed = compressed;
    }

    /**
     * Obtain the 'address hash' per Bitcoin rules.
     *
     * @return 20-byte address hash byte array
     */
    @Nonnull
    @Override
    public byte[] getAddressHash() {
        return Hash.keyHash(encodedPublicKey);
    }

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key or null if not present.
     */
    @CheckForNull
    @Override
    public byte[] exportPrivate() {
        return null;
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return false - the private key is not present.
     */
    @Override
    public boolean hasPrivate() {
        return false;
    }

    /**
     * Export the public key in ASN.1-encoded form.
     *
     * @return ASN.1 encoded public key bytes.
     */
    @Nonnull
    @Override
    public byte[] exportPublic() {
        return Arrays.copyOf(encodedPublicKey, encodedPublicKey.length);
    }

    /**
     * Perform an ECDSA signature using the private key.
     * This public key implementation outright fails because it is unsupported.
     *
     * @param hash
     *         byte array to sign.
     *
     * @return ASN.1 representation of the signature.
     */
    @Nonnull
    @Override
    public byte[] sign(@Nonnull byte[] hash) {
        throw new UnsupportedOperationException("Cannot sign with public key");
    }

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
    @SuppressWarnings("checkstyle:localvariablename")
    @Override
    public boolean verify(@Nonnull byte[] hash, @Nonnull byte[] signature) {
        ASN1InputStream asn1 = new ASN1InputStream(signature);
        try {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(encodedPublicKey), domain));
            DLSequence seq = (DLSequence) asn1.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
            return signer.verifySignature(hash, r, s);
        } catch (Exception e) {
            // treat format errors as invalid signatures
            return false;
        } finally {
            try {
                asn1.close();
            } catch (IOException e) {
                /* squelch */
            }
        }
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    @Nonnull
    @Override
    public ECKey getPublic() {
        return this;
    }

    /**
     * Return true if this is equivalent to the passed in object (same type and same properties).
     *
     * @param obj
     *         instance to compare against.
     *
     * @return true if the values are equivalent, else false.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        BouncyCastleECPublicKey that = (BouncyCastleECPublicKey) obj;
        return Objects.equal(compressed, that.compressed)
                && Arrays.equals(encodedPublicKey, that.encodedPublicKey);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(Arrays.hashCode(encodedPublicKey), compressed);
    }
}