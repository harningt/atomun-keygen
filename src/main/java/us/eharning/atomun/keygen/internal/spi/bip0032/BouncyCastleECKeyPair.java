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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import us.eharning.atomun.keygen.base.ECKey;
import us.eharning.atomun.keygen.base.ValidationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * ECKey implementation wrapping a full keypair using BouncyCastle.
 */
@Immutable
class BouncyCastleECKeyPair extends BouncyCastleECPublicKey {
    @Nonnull
    private final BigInteger privateExponent;

    /**
     * Construct a new EC keypair given the private exponent and whether or not to use compressed point form.
     *
     * @param privateExponent
     *         value defining the private key.
     * @param compressed
     *         whether or not to use compressed point form.
     */
    public BouncyCastleECKeyPair(@Nonnull BigInteger privateExponent, boolean compressed) {
        this(privateExponent, curve.getG().multiply(privateExponent).getEncoded(compressed), compressed);
    }

    /**
     * Construct a new EC keypair given the private exponent, its public point, and whether or not to use compressed point form.
     *
     * @param privateExponent
     *         value defining the private key.
     * @param encodedPublicKey
     *         DER-encoded public point associated with the given private key.
     * @param compressed
     *         whether or not to use compressed point form.
     */
    public BouncyCastleECKeyPair(@Nonnull BigInteger privateExponent, @Nonnull byte[] encodedPublicKey, boolean compressed) {
        super(encodedPublicKey, compressed);
        Preconditions.checkNotNull(privateExponent);
        this.privateExponent = privateExponent;
    }

    /**
     * Utility method to create a new random EC keypair.
     *
     * @param compressed
     *         whether or not to use compressed point form.
     *
     * @return random EC keypair.
     */
    @Nonnull
    public static BouncyCastleECKeyPair createNew(boolean compressed) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(domain, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();

        return new BouncyCastleECKeyPair(privParams.getD(), pubParams.getQ().getEncoded(compressed), compressed);
    }

    /**
     * Import the serialized EC private key given its private exponent as a byte array.
     *
     * @param serializedPrivateExponent
     *         byte array containing value defining the private key.
     * @param compressed
     *         whether or not to use compressed point form.
     *
     * @return the decoded EC private key.
     *
     * @throws ValidationException
     *         if the key is invalid.
     */
    @Nonnull
    public static BouncyCastleECKeyPair importSerialized(@Nonnull byte[] serializedPrivateExponent, boolean compressed) throws ValidationException {
        Preconditions.checkNotNull(serializedPrivateExponent);
        if (serializedPrivateExponent.length != 32) {
            throw new ValidationException("Invalid private key");
        }
        return new BouncyCastleECKeyPair(new BigInteger(1, serializedPrivateExponent).mod(curve.getN()), compressed);
    }

    /**
     * Serialize the EC keypair in WIF Base58-encoded form.
     *
     * @param key
     *         instance to seralize.
     *
     * @return serialized EC keypair.
     */
    @Nonnull
    public static String serializeWIF(@Nonnull BouncyCastleECKeyPair key) {
        return Base58.encode(bytesWIF(key));
    }

    /**
     * Serialize the EC keypair as a WIF byte array.
     *
     * @param key
     *         instance to serialize.
     *
     * @return serialized EC keypair.
     */
    @SuppressWarnings("checkstyle:localvariablename")
    @Nonnull
    private static byte[] bytesWIF(@Nonnull BouncyCastleECKeyPair key) {
        byte[] k = key.exportPrivate();
        if (key.compressed) {
            final byte[] encoded = new byte[k.length + 6];
            final byte[] ek = new byte[k.length + 2];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            ek[k.length + 1] = 0x01;
            final byte[] hash = Hash.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        } else {
            final byte[] encoded = new byte[k.length + 5];
            final byte[] ek = new byte[k.length + 1];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            final byte[] hash = Hash.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        }
    }

    @Nonnull
    public static BouncyCastleECKeyPair parseWIF(@Nonnull String serialized) throws ValidationException {
        byte[] store = Base58.decode(serialized);
        return parseBytesWIF(store);
    }

    @Nonnull
    public static BouncyCastleECKeyPair parseBytesWIF(@Nonnull byte[] store) throws ValidationException {
        if (store.length == 37) {
            verifyChecksum(store);
            byte[] key = new byte[store.length - 5];
            System.arraycopy(store, 1, key, 0, store.length - 5);
            return importSerialized(key, false);
        } else if (store.length == 38) {
            verifyChecksum(store);
            byte[] key = new byte[store.length - 6];
            System.arraycopy(store, 1, key, 0, store.length - 6);
            return importSerialized(key, true);
        }
        throw new ValidationException("Invalid key length");
    }

    private static void verifyChecksum(@Nonnull byte[] store) throws ValidationException {
        byte[] checksum = new byte[4];
        System.arraycopy(store, store.length - 4, checksum, 0, 4);
        byte[] ekey = new byte[store.length - 4];
        System.arraycopy(store, 0, ekey, 0, store.length - 4);
        byte[] hash = Hash.hash(ekey);
        for (int i = 0; i < 4; ++i) {
            if (hash[i] != checksum[i]) {
                throw new ValidationException("Checksum mismatch");
            }
        }
    }

    /**
     * Export the private key in bitcoin 'standard' form - exactly 32-bytes.
     *
     * @return exported 32-byte private key.
     */
    @Nonnull
    @Override
    public byte[] exportPrivate() {
        byte[] privateBytes = privateExponent.toByteArray();
        if (privateBytes.length != 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(privateBytes, Math.max(0, privateBytes.length - 32), tmp, Math.max(0, 32 - privateBytes.length), Math.min(32, privateBytes.length));
            privateBytes = tmp;
        }
        return privateBytes;
    }

    /**
     * Returns whether or not this keypair is populated with the private key.
     *
     * @return true - the private key is present.
     */
    @Override
    public boolean hasPrivate() {
        return true;
    }

    /**
     * Obtain a reference to this key, just including public pieces.
     *
     * @return instance with just public data present.
     */
    @Nonnull
    @Override
    public ECKey getPublic() {
        return new BouncyCastleECPublicKey(encodedPublicKey, compressed);
    }

    /**
     * Perform an ECDSA signature using the private key.
     *
     * @param hash
     *         byte array to sign.
     *
     * @return ASN.1 representation of the signature.
     */
    @Nonnull
    @Override
    public byte[] sign(@Nonnull byte[] hash) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateExponent, domain));
        BigInteger[] signature = signer.generateSignature(hash);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator seq = new DERSequenceGenerator(stream);
            seq.addObject(new ASN1Integer(signature[0]));
            seq.addObject(new ASN1Integer(signature[1]));
            seq.close();
            return stream.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("IOException should not be thrown", e);
        }
    }

    /**
     * Convert this instance to a string form - which happens to be the serialized WIF form.
     *
     * @return display string.
     */
    @Override
    public String toString() {
        return serializeWIF(this);
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
        BouncyCastleECKeyPair that = (BouncyCastleECKeyPair) obj;
        return Objects.equal(compressed, that.compressed)
                && Arrays.equals(encodedPublicKey, that.encodedPublicKey)
                && Objects.equal(privateExponent, that.privateExponent);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(compressed, Arrays.hashCode(encodedPublicKey), privateExponent);
    }
}