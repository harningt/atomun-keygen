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
import okio.ByteString
import okio.process
import us.eharning.atomun.core.ec.ECKey
import java.util.*
import javax.annotation.concurrent.Immutable

/**
 * BIP0032 node data.
 *
 * TODO: Embed address base so that appropriate serialization is performed.
 */
@Immutable
internal data class BIP0032Node
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
        val chainCode: ByteString,
        val depth: Int,
        val parent: Int,
        val sequence: Int
) {

    /**
     * Get the node's fingerprint based on the first 4 bytes of the address hash of the master key.
     *
     * @return the node's fingerprint as an integer.
     */
    val fingerPrint: Int
        get() {
            val address = master.addressHash
            return address.process { Ints.fromByteArray(it) }
        }

    /**
     * Obtain whether or not the master key has private bits.
     *
     * @return true if the master key has private bits.
     */
    fun hasPrivate(): Boolean {
        return master.hasPrivate()
    }
}
