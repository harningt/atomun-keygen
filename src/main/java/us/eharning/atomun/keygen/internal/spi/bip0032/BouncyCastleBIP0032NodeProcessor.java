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

import com.google.common.base.Charsets;
import com.google.common.base.Objects;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import us.eharning.atomun.keygen.base.ECKey;
import us.eharning.atomun.keygen.base.ValidationException;
import us.eharning.atomun.keygen.path.BIP0032Path;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * BIP0032 node processing implementation based on BouncyCastle.
 */
final class BouncyCastleBIP0032NodeProcessor implements BIP0032NodeProcessor {
    /**
     * Cache for already-processed node-encodings to avoid unnecessary re-derivation.
     */
    public static final Cache<NodeSequence, BIP0032Node> NODE_CACHE = CacheBuilder.newBuilder().maximumSize(16).recordStats().build();
    private static final SecureRandom rnd = new SecureRandom();
    private static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    private static final byte[] BITCOIN_SEED = "Bitcoin seed".getBytes(Charsets.US_ASCII);
    private static final byte[] xprv = new byte[]{0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4};
    private static final byte[] xpub = new byte[]{0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E};
    private static final byte[] tprv = new byte[]{0x04, (byte) 0x35, (byte) 0x83, (byte) 0x94};
    private static final byte[] tpub = new byte[]{0x04, (byte) 0x35, (byte) 0x87, (byte) 0xCF};

    /**
     * Copy the given data bytes into the output array at a given offset.
     *
     * @param out
     *         array to write into.
     * @param index
     *         offset into the array to write at.
     * @param data
     *         array to write from.
     */
    private static void putBytes(byte[] out, int index, byte[] data) {
        System.arraycopy(data, 0, out, index, data.length);
    }

    /**
     * Store an integer as 4 bytes in a byte array.
     *
     * @param out
     *         array to write into.
     * @param index
     *         offset into the array to write at.
     * @param value
     *         value to write into the array.
     */
    private static void putInt32(@Nonnull byte[] out, int index, int value) {
        out[index] = (byte) (value >> 24);
        out[index + 1] = (byte) (value >> 16);
        out[index + 2] = (byte) (value >> 8);
        out[index + 3] = (byte) value;
    }

    /**
     * Convert 4 bytes of a byte array to an integer.
     *
     * @param in
     *         byte array to obtain the integer from.
     * @param index
     *         offset into the array to start at.
     *
     * @return 32-bit integer from the input byte array.
     */
    private static int getInt32(@Nonnull byte[] in, int index) {
        return (in[index] & 0xff) << 24
                | (in[index + 1] & 0xff) << 16
                | (in[index + 2] & 0xff) << 8
                | (in[index + 3] & 0xff);
    }

    /**
     * Convert the node into a Base58+checksum encoded string.
     *
     * @param node
     *         instance to encode.
     *
     * @return Base58+checksum encoded string.
     */
    @Override
    public String exportNode(BIP0032Node node) {
        /* Assume production - TODO: allow custom address bases */
        final boolean production = true;
        final ECKey master = node.getMaster();
        byte[] out = new byte[78];
        if (master.hasPrivate()) {
            if (production) {
                putBytes(out, 0, xprv);
            } else {
                putBytes(out, 0, tprv);
            }
        } else {
            if (production) {
                putBytes(out, 0, xpub);
            } else {
                putBytes(out, 0, tpub);
            }
        }
        out[4] = (byte) (node.getDepth() & 0xff);
        putInt32(out, 5, node.getParent());
        putInt32(out, 9, node.getSequence());
        putBytes(out, 13, node.getChainCode());
        if (master.hasPrivate()) {
            out[45] = 0x00;
            byte[] privateKey = master.exportPrivate();
            assert (null != privateKey);
            putBytes(out, 46, privateKey);
        } else {
            putBytes(out, 45, master.exportPublic());
        }
        return Base58.encodeWithChecksum(out);
    }

    /**
     * Convert the Base58+checksum encoded string into a BIP0032 node.
     *
     * @param serialized
     *         encoded string to decode.
     *
     * @return BIP0032 node represented by the serialized string.
     *
     * @throws ValidationException
     *         if the data is not a valid encoded BIP0032 node.
     */
    @Override
    public BIP0032Node importNode(String serialized) throws ValidationException {
        byte[] data = Base58.decodeWithChecksum(serialized);
        if (data.length != 78) {
            throw new ValidationException("Invalid extended key value");
        }
        byte[] type = Arrays.copyOf(data, 4);
        boolean hasPrivate;
        if (Arrays.areEqual(type, xprv) || Arrays.areEqual(type, tprv)) {
            hasPrivate = true;
        } else if (Arrays.areEqual(type, xpub) || Arrays.areEqual(type, tpub)) {
            hasPrivate = false;
        } else {
            throw new ValidationException("Invalid magic number for an extended key");
        }
        int depth = data[4] & 0xff;
        int parent = getInt32(data, 5);
        int sequence = getInt32(data, 9);
        byte[] chainCode = Arrays.copyOfRange(data, 13, 13 + 32);
        byte[] pubOrPriv = Arrays.copyOfRange(data, 13 + 32, data.length);
        ECKey key;
        if (hasPrivate) {
            key = new BouncyCastleECKeyPair(new BigInteger(1, pubOrPriv), true);
        } else {
            key = new BouncyCastleECPublicKey(pubOrPriv, true);
        }
        return new BIP0032Node(key, chainCode, depth, parent, sequence);
    }

    /**
     * Generates a BIP0032 node from a seed value that is passed through a basic HMAC process.
     *
     * @param seed
     *         value for which the node should be generated.
     *
     * @return BIP0032 node deterministically based on the seed input.
     *
     * @throws ValidationException
     *         if either cryptography fails (unlikely)
     *         or the seed results in an invalid EC key (unlikely).
     */
    /* BITCOIN_SEED is not a password but instead a shared key to mask the seed input */
    @SuppressFBWarnings("HARD_CODE_PASSWORD")
    @SuppressWarnings("checkstyle:localvariablename")
    @Override
    public BIP0032Node generateNodeFromSeed(byte[] seed) throws ValidationException {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            SecretKey seedkey = new SecretKeySpec(BITCOIN_SEED, "HmacSHA512");
            mac.init(seedkey);
            byte[] lr = mac.doFinal(seed);
            byte[] l = Arrays.copyOfRange(lr, 0, 32);
            byte[] r = Arrays.copyOfRange(lr, 32, 64);
            BigInteger m = new BigInteger(1, l);
            if (m.compareTo(curve.getN()) >= 0 || m.compareTo(BigInteger.ZERO) == 0) {
                throw new ValidationException("Invalid chain value generated");
            }
            BouncyCastleECKeyPair keyPair = new BouncyCastleECKeyPair(m, true);
            return new BIP0032Node(keyPair, r, 0, 0, 0);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ValidationException(e);
        }
    }

    /**
     * Generates a random BIP0032 node.
     *
     * @return BIP0032 node randomly generated.
     */
    @Override
    public BIP0032Node generateNode() {
        ECKey key = BouncyCastleECKeyPair.createNew(true);
        byte[] chainCode = new byte[32];
        rnd.nextBytes(chainCode);
        return new BIP0032Node(key, chainCode, 0, 0, 0);
    }

    /**
     * Utility method to perform 'I' value derivation.
     *
     * @param node
     *         BIP0032 base node.
     * @param sequence
     *         value to use for derivation.
     *
     * @return derived BIP0032 node.
     *
     * @throws NoSuchAlgorithmException
     *         if somehow HmacSHA512 cannot be found (unlikely).
     * @throws InvalidKeyException
     *         if the chain code is somehow not a value HmacSHA512 key (unlikely).
     */
    @Nonnull
    private byte[] deriveI(@Nonnull BIP0032Node node, int sequence) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA512");
        SecretKey key = new SecretKeySpec(node.getChainCode(), "HmacSHA512");
        mac.init(key);
        byte[] extended;
        if ((sequence & 0x80000000) == 0) {
            byte[] pub = node.getMaster().exportPublic();
            extended = java.util.Arrays.copyOf(pub, pub.length + 4);
            putInt32(extended, pub.length, sequence);
        } else {
            byte[] priv = node.getMaster().exportPrivate();
            assert (null != priv);
            extended = new byte[priv.length + 5];
            /* Offset of 1 to account for extra zero at front */
            System.arraycopy(priv, 0, extended, 1, priv.length);
            putInt32(extended, priv.length + 1, sequence);
        }
        return mac.doFinal(extended);
    }

    /**
     * Derives a BIP0032 node given the input path.
     *
     * @param node
     *         base node to derive from.
     * @param path
     *         set of sequence values to use for derivation.
     *
     * @return BIP0032 node derived using the necessary algorithms per BIP0032 specification.
     *
     * @throws ValidationException
     *         if it is impossible to generate a key using the path,
     *         it is impossible to derive a key due to missing private bits,
     *         or the resultant key is an invalid EC key (unlikely).
     */
    @Override
    public BIP0032Node deriveNode(BIP0032Node node, BIP0032Path path) throws ValidationException {
        BIP0032Node current = node;
        /* NOTE: since relative paths aren't possible yet with path object, must derive from root */
        if (current.getDepth() != 0) {
            throw new ValidationException("Wrong depth for root-based path");
        }
        for (Integer sequence : path) {
            current = deriveNode(current, sequence);
        }
        return current;
    }

    /**
     * Derives a BIP0032 node given the singular sequence value.
     *
     * @param node
     *         base node to derive from.
     * @param sequence
     *         value to use for derivation.
     *
     * @return BIP0032 node derived using the necessary algorithms per BIP0032 specification.
     *
     * @throws ValidationException
     *         it is impossible to derive a key due to missing private bits,
     *         or the resultant key is an invalid EC key (unlikely).
     */
    @SuppressWarnings("checkstyle:localvariablename")
    @Override
    public BIP0032Node deriveNode(BIP0032Node node, int sequence) throws ValidationException {
        NodeSequence nodeSequence = new NodeSequence(node, sequence);
        BIP0032Node cached = NODE_CACHE.getIfPresent(nodeSequence);
        if (null != cached) {
            return cached;
        }
        final ECKey master = node.getMaster();
        try {
            if ((sequence & 0x80000000) != 0 && master.exportPrivate() == null) {
                throw new ValidationException("Need private key for private generation");
            }
            byte[] lr = deriveI(node, sequence);

            byte[] l = java.util.Arrays.copyOfRange(lr, 0, 32);
            byte[] r = java.util.Arrays.copyOfRange(lr, 32, 64);
            BigInteger m = new BigInteger(1, l);
            if (m.compareTo(curve.getN()) >= 0 || m.compareTo(BigInteger.ZERO) == 0) {
                throw new ValidationException("Invalid chain value generated");
            }
            if (master.hasPrivate()) {
                byte[] priv = master.exportPrivate();
                assert (null != priv);
                BigInteger k = m.add(new BigInteger(1, priv)).mod(curve.getN());
                if (k.compareTo(BigInteger.ZERO) == 0) {
                    throw new ValidationException("Invalid private node generated");
                }
                cached = new BIP0032Node(new BouncyCastleECKeyPair(k, true), r, node.getDepth() + 1, node.getFingerPrint(), sequence);
                NODE_CACHE.put(nodeSequence, cached);
                return cached;
            } else {
                byte[] pub = master.exportPublic();
                ECPoint q = curve.getG().multiply(m).add(curve.getCurve().decodePoint(pub));
                if (q.isInfinity()) {
                    throw new ValidationException("Invalid public node generated");
                }
                pub = q.getEncoded(true);
                cached = new BIP0032Node(new BouncyCastleECPublicKey(pub, true), r, node.getDepth() + 1, node.getFingerPrint(), sequence);
                NODE_CACHE.put(nodeSequence, cached);
                return cached;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ValidationException(e);
        }
    }

    /**
     * Obtain the BIP0032 node without its private bits (if present).
     *
     * @param node
     *         instance to obtain a version of without private bits.
     *
     * @return BIP0032 node instance without private bits.
     */
    public BIP0032Node getPublic(BIP0032Node node) {
        if (!node.hasPrivate()) {
            return node;
        }
        final BouncyCastleECPublicKey master = new BouncyCastleECPublicKey(node.getMaster().exportPublic(), true);
        return new BIP0032Node(master, node.getChainCode(), node.getDepth(), node.getParent(), node.getSequence());
    }

    /**
     * Utility class wrapping a BIP0032Node+sequence pair for cache identity entry.
     */
    private static final class NodeSequence {
        private final BIP0032Node node;
        private final int sequence;

        /**
         * Construct a new pair.
         *
         * @param node
         *         BIP0032 base node.
         * @param sequence
         *         index into BIP0032 base node.
         */
        public NodeSequence(@Nonnull BIP0032Node node, int sequence) {
            this.node = node;
            this.sequence = sequence;
        }

        /**
         * Returns whether this pair is equivalent to another.
         *
         * @param obj
         *         instance to compare against.
         *
         * @return true if the objects are identical, false otherwise.
         */
        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            NodeSequence that = (NodeSequence) obj;
            return Objects.equal(sequence, that.sequence)
                    && Objects.equal(node, that.node);
        }

        /**
         * Returns a hash code value for the object.
         *
         * @return a hash code value for this object.
         */
        @Override
        public int hashCode() {
            return Objects.hashCode(node, sequence);
        }
    }
}
