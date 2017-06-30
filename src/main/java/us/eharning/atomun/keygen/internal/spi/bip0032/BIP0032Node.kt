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

import com.google.common.primitives.Ints
import us.eharning.atomun.core.ec.ECKey
import java.util.*
import javax.annotation.concurrent.Immutable

/**
 * BIP0032 node data.
 *
 * TODO: Embed address base so that appropriate serialization is performed.
 */
@Immutable
internal class BIP0032Node
/**
 * Construct a BIP0032 node with the given properties.
 *
 * @param master
 *         master key for this node.
 * @param chainCode
 *         chain code byte array.
 * @param depth
 *         depth into the BIP0032 hierarchy.
 * @param parent
 *         parent node's fingerprint.
 * @param sequence
 *         sequence into the parent node.
 */
(
        val master: ECKey,
        chainCode: ByteArray,
        val depth: Int,
        val parent: Int,
        val sequence: Int
) {
    private val chainCode: ByteArray = chainCode.copyOf()

    /**
     * Get the node's chain code.
     *
     * @return the node's chain code as a byte array copy.
     */
    fun getChainCode(): ByteArray {
        return Arrays.copyOf(chainCode, chainCode.size)
    }

    /**
     * Get the node's fingerprint based on the first 4 bytes of the address hash of the master key.
     *
     * @return the node's fingerprint as an integer.
     */
    val fingerPrint: Int
        get() {
            val address = master.addressHash
            return Ints.fromByteArray(address)
        }

    /**
     * Obtain whether or not the master key has private bits.
     *
     * @return true if the master key has private bits.
     */
    fun hasPrivate(): Boolean {
        return master.hasPrivate()
    }

    /**
     * Return true if this is equivalent to the passed in object (same type and same properties).
     *
     * @param other
     *         instance to compare against.
     *
     * @return true if the values are equivalent, else false.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (javaClass != other?.javaClass) {
            return false
        }
        other as BIP0032Node
        return depth == other.depth
                && sequence == other.sequence
                && master == other.master
                && parent == other.parent
                && Arrays.equals(chainCode, other.chainCode)
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    override fun hashCode(): Int {
        var result = master.hashCode()
        result = 31 * result + depth
        result = 31 * result + parent
        result = 31 * result + sequence
        result = 31 * result + Arrays.hashCode(chainCode)
        return result
    }
}
