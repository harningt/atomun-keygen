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
import okio.ByteString
import okio.ByteStrings
import okio.copyTo
import okio.process
import okio.toBigInteger
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
                out.putBytes(0, xprv)
            } else {
                out.putBytes(0, tprv)
            }
        } else {
            if (production) {
                out.putBytes(0, xpub)
            } else {
                out.putBytes(0, tpub)
            }
        }
        out.putInt8(4, node.depth)
        out.putInt32(5, node.parent)
        out.putInt32(9, node.sequence)
        out.putBytes(13, node.chainCode)
        if (master.hasPrivate()) {
            out[45] = 0x00
            val privateKey = master.exportPrivate()!!
            out.putBytes(46, privateKey)
        } else {
            out.putBytes(45, master.exportPublic())
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
        val depth = data.getInt8(4)
        val parent = data.getInt32(5)
        val sequence = data.getInt32(9)
        val chainCode = data.getBytes(13, 32)
        val pubOrPriv = data.getBytes(13 + 32)
        val key: ECKey
        if (hasPrivate) {
            val secretExponent = pubOrPriv.toBigInteger()
            key = ECKeyFactory.instance.fromSecretExponent(secretExponent, compressed = true)
        } else {
            key = ECKeyFactory.instance.fromEncodedPublicKey(pubOrPriv, true)
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
    override fun generateNodeFromSeed(seed: ByteString): BIP0032Node {
        try {
            val lr = seed.hmacSha512(BITCOIN_SEED)
            val l = lr.substring(0, 32)
            val r = lr.substring(32, 64)
            val m = l.toBigInteger()
            if (m >= curve.n || m == BigInteger.ZERO) {
                throw ValidationException("Invalid chain value generated")
            }
            val keyPair = ECKeyFactory.instance.fromSecretExponent(m, compressed = true)
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
        val key = ECKeyFactory.instance.generateRandom(true)
        val chainCode = ByteArray(32)
        rnd.nextBytes(chainCode)
        return BIP0032Node(key, ByteStrings.takeOwnership(chainCode), 0, 0, 0)
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
    private fun deriveI(node: BIP0032Node, sequence: Int): ByteString {
        val mac = Mac.getInstance("HmacSHA512")
        val key = node.chainCode.process { SecretKeySpec(it, "HmacSHA512") }
        mac.init(key)
        val extended: ByteArray
        if (sequence and PRIVATE_FLAG == 0) {
            val pub = node.master.exportPublic()
            extended = ByteArray(pub.size() + 4)
            extended.putBytes(0, pub)
            extended.putInt32(pub.size(), sequence)
        } else {
            val priv = node.master.exportPrivate()!!
            extended = ByteArray(priv.size() + 5)
            /* Offset of 1 to account for extra zero at front */
            extended.putBytes(1, priv)
            extended.putInt32(priv.size() + 1, sequence)
        }
        return ByteStrings.takeOwnership(mac.doFinal(extended))
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
                if (sequence and PRIVATE_FLAG != 0 && !master.hasPrivate()) {
                    throw ValidationException("Need private key for private generation")
                }
                val lr = deriveI(node, sequence)

                val l = lr.substring(0, 32)
                val r = lr.substring(32, 64)
                val m = l.toBigInteger()
                if (m >= curve.n || m == BigInteger.ZERO) {
                    throw ValidationException("Invalid chain value generated")
                }
                if (master.hasPrivate()) {
                    val private = master.exportPrivate()!!
                    val k = (m + private.toBigInteger()).mod(curve.n)
                    if (k == BigInteger.ZERO) {
                        throw ValidationException("Invalid private node generated")
                    }
                    return@get BIP0032Node(ECKeyFactory.instance.fromSecretExponent(k, null, true), r, node.depth + 1, node.fingerPrint, sequence)
                } else {
                    val public = master.exportPublic()
                    val publicPoint = public.process { curve.curve.decodePoint(it) }
                    val q = curve.g.multiply(m).add(publicPoint)
                    if (q.isInfinity) {
                        throw ValidationException("Invalid public node generated")
                    }
                    val encodedPublicKey = ByteStrings.takeOwnership(q.getEncoded(true))
                    return@get BIP0032Node(ECKeyFactory.instance.fromEncodedPublicKey(encodedPublicKey, true), r, node.depth + 1, node.fingerPrint, sequence)
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
        val master = ECKeyFactory.instance.fromEncodedPublicKey(node.master.exportPublic(), true)
        return BIP0032Node(master, node.chainCode, node.depth, node.parent, node.sequence)
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
        private val BITCOIN_SEED = ByteString.encodeString("Bitcoin seed", Charsets.US_ASCII)
        private val xprv = byteArrayOf(0x04, 0x88.toByte(), 0xAD.toByte(), 0xE4.toByte())
        private val xpub = byteArrayOf(0x04, 0x88.toByte(), 0xB2.toByte(), 0x1E.toByte())
        private val tprv = byteArrayOf(0x04, 0x35.toByte(), 0x83.toByte(), 0x94.toByte())
        private val tpub = byteArrayOf(0x04, 0x35.toByte(), 0x87.toByte(), 0xCF.toByte())

        private val PRIVATE_FLAG: Int = 0x80000000.toInt()
    }
}

/**
 * Copy the given data bytes into the output array at a given offset.
 *
 * @param index
 *         offset into the array to write at.
 * @param data
 *         array to write from.
 */
private fun ByteArray.putBytes(index: Int, data: ByteArray) {
    System.arraycopy(data, 0, this, index, data.size)
}

/**
 * Copy the given data bytes into the output array at a given offset.
 *
 * @param index
 *         offset into the array to write at.
 * @param data
 *         array to write from.
 */
private fun ByteArray.putBytes(index: Int, data: ByteString) {
    data.copyTo(this, index)
}

/**
 * Store an integer as 1 bytes in a byte array.
 *
 * @param index
 *         offset into the array to write at.
 * @param value
 *         value to write into the array.
 */
private fun ByteArray.putInt8(index: Int, value: Int) {
    this[index] = (value and 0xff).toByte()
}

/**
 * Store an integer as 4 bytes in a byte array.
 *
 * @param index
 *         offset into the array to write at.
 * @param value
 *         value to write into the array.
 */
private fun ByteArray.putInt32(index: Int, value: Int) {
    this[index] = (value shr 24).toByte()
    this[index + 1] = (value shr 16).toByte()
    this[index + 2] = (value shr 8).toByte()
    this[index + 3] = value.toByte()
}

/**
 * Extract a ByteString from a byte array.
 *
 * @param index
 *         offset into the array to read from.
 * @param length
 *         how many bytes to extract.
 *         Default: from index to end
 */
private fun ByteArray.getBytes(index: Int, length: Int = size - index): ByteString {
    return ByteString.of(this, index, length)
}

/**
 * Convert 1 byte (treated as unsigned) of a byte array to an integer.
 *
 * @param index
 *         offset into the array to start at.
 *
 * @return 8-bit integer from the input byte array.
 */
private fun ByteArray.getInt8(index: Int): Int {
    return this[index].toInt() and 0xff
}

/**
 * Convert 4 bytes of a byte array to an integer.
 *
 * @param index
 *         offset into the array to start at.
 *
 * @return 32-bit integer from the input byte array.
 */
private fun ByteArray.getInt32(index: Int): Int {
    return this[index].toInt() and 0xff shl 24 or
            (this[index + 1].toInt() and 0xff shl 16) or
            (this[index + 2].toInt() and 0xff shl 8) or
            (this[index + 3].toInt() and 0xff)
}
