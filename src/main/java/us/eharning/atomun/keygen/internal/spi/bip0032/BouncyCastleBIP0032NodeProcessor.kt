/*
 * Copyright 2015, 2017 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.keygen.internal.spi.bip0032

import com.google.common.base.Charsets
import com.google.common.cache.CacheBuilder
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import org.bouncycastle.asn1.sec.SECNamedCurves
import us.eharning.atomun.core.ValidationException
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.core.ec.ECKeyFactory
import us.eharning.atomun.core.encoding.Base58
import us.eharning.atomun.keygen.path.BIP0032Path
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * BIP0032 node processing implementation based on BouncyCastle.
 */
internal class BouncyCastleBIP0032NodeProcessor : BIP0032NodeProcessor {

    /**
     * Convert the node into a Base58+checksum encoded string.
     *
     * @param node
     *         instance to encode.
     *
     * @return Base58+checksum encoded string.
     */
    override fun exportNode(node: BIP0032Node): String {
        /* Assume production - TODO: allow custom address bases */
        val production = true
        val master = node.master
        val out = ByteArray(78)
        if (master.hasPrivate()) {
            if (production) {
                putBytes(out, 0, xprv)
            } else {
                putBytes(out, 0, tprv)
            }
        } else {
            if (production) {
                putBytes(out, 0, xpub)
            } else {
                putBytes(out, 0, tpub)
            }
        }
        out[4] = (node.depth and 0xff).toByte()
        putInt32(out, 5, node.parent)
        putInt32(out, 9, node.sequence)
        putBytes(out, 13, node.getChainCode())
        if (master.hasPrivate()) {
            out[45] = 0x00
            val privateKey = master.exportPrivate()!!
            putBytes(out, 46, privateKey)
        } else {
            putBytes(out, 45, master.exportPublic())
        }
        return Base58.encodeWithChecksum(out)
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
    @Throws(ValidationException::class)
    override fun importNode(serialized: String): BIP0032Node {
        val data = Base58.decodeWithChecksum(serialized)
        if (data.size != 78) {
            throw ValidationException("Invalid extended key value")
        }
        val type = data.copyOf(4)
        val hasPrivate: Boolean
        if (type.contentEquals(xprv) || type.contentEquals(tprv)) {
            hasPrivate = true
        } else if (type.contentEquals(xpub) || type.contentEquals(tpub)) {
            hasPrivate = false
        } else {
            throw ValidationException("Invalid magic number for an extended key")
        }
        val depth = data[4].toInt() and 0xff
        val parent = getInt32(data, 5)
        val sequence = getInt32(data, 9)
        val chainCode = data.copyOfRange(13, 13 + 32)
        val pubOrPriv = data.copyOfRange(13 + 32, data.size)
        val key: ECKey
        if (hasPrivate) {
            key = ECKeyFactory.getInstance().fromSecretExponent(BigInteger(1, pubOrPriv), true)
        } else {
            key = ECKeyFactory.getInstance().fromEncodedPublicKey(pubOrPriv, true)
        }
        return BIP0032Node(key, chainCode, depth, parent, sequence)
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
    @Throws(ValidationException::class)
    override fun generateNodeFromSeed(seed: ByteArray): BIP0032Node {
        try {
            val mac = Mac.getInstance("HmacSHA512")
            val seedkey = SecretKeySpec(BITCOIN_SEED, "HmacSHA512")
            mac.init(seedkey)
            val lr = mac.doFinal(seed)
            val l = lr.copyOfRange(0, 32)
            val r = lr.copyOfRange(32, 64)
            val m = BigInteger(1, l)
            if (m >= curve.n || m == BigInteger.ZERO) {
                throw ValidationException("Invalid chain value generated")
            }
            val keyPair = ECKeyFactory.getInstance().fromSecretExponent(m, true)
            return BIP0032Node(keyPair, r, 0, 0, 0)
        } catch (e: NoSuchAlgorithmException) {
            throw ValidationException(e)
        } catch (e: InvalidKeyException) {
            throw ValidationException(e)
        }

    }

    /**
     * Generates a random BIP0032 node.
     *
     * @return BIP0032 node randomly generated.
     */
    override fun generateNode(): BIP0032Node {
        val key = ECKeyFactory.getInstance().generateRandom(true)
        val chainCode = ByteArray(32)
        rnd.nextBytes(chainCode)
        return BIP0032Node(key, chainCode, 0, 0, 0)
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
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    private fun deriveI(node: BIP0032Node, sequence: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        val key = SecretKeySpec(node.getChainCode(), "HmacSHA512")
        mac.init(key)
        val extended: ByteArray
        if (sequence and 0x80000000.toInt() == 0) {
            val pub = node.master.exportPublic()
            extended = pub.copyOf(pub.size + 4)
            putInt32(extended, pub.size, sequence)
        } else {
            val priv = node.master.exportPrivate()!!
            extended = ByteArray(priv.size + 5)
            /* Offset of 1 to account for extra zero at front */
            System.arraycopy(priv, 0, extended, 1, priv.size)
            putInt32(extended, priv.size + 1, sequence)
        }
        return mac.doFinal(extended)
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
    @Throws(ValidationException::class)
    override fun deriveNode(node: BIP0032Node, path: BIP0032Path): BIP0032Node {
        var current = node
        /* NOTE: since relative paths aren't possible yet with path object, must derive from root */
        if (current.depth != 0) {
            throw ValidationException("Wrong depth for root-based path")
        }
        for (sequence in path) {
            current = deriveNode(current, sequence)
        }
        return current
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
    @Throws(ValidationException::class)
    override fun deriveNode(node: BIP0032Node, sequence: Int): BIP0032Node {
        val nodeSequence = NodeSequence(node, sequence)
        return NODE_CACHE.get(nodeSequence) {
            val master = node.master
            try {
                if (sequence and 0x80000000.toInt() != 0 && master.exportPrivate() == null) {
                    throw ValidationException("Need private key for private generation")
                }
                val lr = deriveI(node, sequence)

                val l = lr.copyOfRange(0, 32)
                val r = lr.copyOfRange(32, 64)
                val m = BigInteger(1, l)
                if (m >= curve.n || m == BigInteger.ZERO) {
                    throw ValidationException("Invalid chain value generated")
                }
                if (master.hasPrivate()) {
                    val priv = master.exportPrivate()!!
                    val k = (m + BigInteger(1, priv)) % curve.n
                    if (k == BigInteger.ZERO) {
                        throw ValidationException("Invalid private node generated")
                    }
                    return@get BIP0032Node(ECKeyFactory.getInstance().fromSecretExponent(k, true), r, node.depth + 1, node.fingerPrint, sequence)
                } else {
                    var pub = master.exportPublic()
                    val q = curve.g.multiply(m).add(curve.curve.decodePoint(pub))
                    if (q.isInfinity) {
                        throw ValidationException("Invalid public node generated")
                    }
                    pub = q.getEncoded(true)
                    return@get BIP0032Node(ECKeyFactory.getInstance().fromEncodedPublicKey(pub, true), r, node.depth + 1, node.fingerPrint, sequence)
                }
            } catch (e: NoSuchAlgorithmException) {
                throw ValidationException(e)
            } catch (e: InvalidKeyException) {
                throw ValidationException(e)
            }
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
    override fun getPublic(node: BIP0032Node): BIP0032Node {
        if (!node.hasPrivate()) {
            return node
        }
        val master = ECKeyFactory.getInstance().fromEncodedPublicKey(node.master.exportPublic(), true)
        return BIP0032Node(master, node.getChainCode(), node.depth, node.parent, node.sequence)
    }

    /**
     * Utility class wrapping a BIP0032Node+sequence pair for cache identity entry.
     */
    private data class NodeSequence
    /**
     * Construct a new pair.
     *
     * @param node
     *         BIP0032 base node.
     * @param sequence
     *         index into BIP0032 base node.
     */
    (private val node: BIP0032Node, private val sequence: Int)

    companion object {
        /**
         * Cache for already-processed node-encodings to avoid unnecessary re-derivation.
         */
        private val NODE_CACHE = CacheBuilder.newBuilder().maximumSize(16).recordStats().build<NodeSequence, BIP0032Node>()
        private val rnd = SecureRandom()
        private val curve = SECNamedCurves.getByName("secp256k1")
        private val BITCOIN_SEED = "Bitcoin seed".toByteArray(Charsets.US_ASCII)
        private val xprv = byteArrayOf(0x04, 0x88.toByte(), 0xAD.toByte(), 0xE4.toByte())
        private val xpub = byteArrayOf(0x04, 0x88.toByte(), 0xB2.toByte(), 0x1E.toByte())
        private val tprv = byteArrayOf(0x04, 0x35.toByte(), 0x83.toByte(), 0x94.toByte())
        private val tpub = byteArrayOf(0x04, 0x35.toByte(), 0x87.toByte(), 0xCF.toByte())

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
        private fun putBytes(out: ByteArray, index: Int, data: ByteArray) {
            System.arraycopy(data, 0, out, index, data.size)
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
        private fun putInt32(out: ByteArray, index: Int, value: Int) {
            out[index] = (value shr 24).toByte()
            out[index + 1] = (value shr 16).toByte()
            out[index + 2] = (value shr 8).toByte()
            out[index + 3] = value.toByte()
        }

        /**
         * Convert 4 bytes of a byte array to an integer.
         *
         * @param input
         *         byte array to obtain the integer from.
         * @param index
         *         offset into the array to start at.
         *
         * @return 32-bit integer from the input byte array.
         */
        private fun getInt32(input: ByteArray, index: Int): Int {
            return input[index].toInt() and 0xff shl 24 or
                    (input[index + 1].toInt() and 0xff shl 16) or
                    (input[index + 2].toInt() and 0xff shl 8) or
                    (input[index + 3].toInt() and 0xff)
        }
    }
}
