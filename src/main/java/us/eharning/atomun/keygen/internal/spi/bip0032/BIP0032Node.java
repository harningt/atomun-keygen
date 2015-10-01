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
import com.google.common.primitives.Ints;
import us.eharning.atomun.keygen.base.ECKey;

import java.util.Arrays;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * BIP0032 node data.
 * <p>
 * TODO: Embed address base so that appropriate serialization is performed.
 * </p>
 */
@Immutable
final class BIP0032Node {
    private final ECKey master;
    private final byte[] chainCode;
    private final int depth;
    private final int parent;
    private final int sequence;

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
    BIP0032Node(@Nonnull ECKey master, @Nonnull byte[] chainCode, int depth, int parent, int sequence) {
        this.master = master;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = depth;
        this.parent = parent;
        this.sequence = sequence;
    }

    /**
     * Get the node's master key.
     *
     * @return the node's master key.
     */
    @Nonnull
    public ECKey getMaster() {
        return master;
    }

    /**
     * Get the node's chain code.
     *
     * @return the node's chain code as a byte array copy.
     */
    @Nonnull
    public byte[] getChainCode() {
        return Arrays.copyOf(chainCode, chainCode.length);
    }

    /**
     * Get the depth into the BIP0032 hierarchy.
     *
     * @return BIP0032 hierarchy depth.
     */
    public int getDepth() {
        return depth;
    }

    /**
     * Get the node's fingerprint based on the first 4 bytes of the address hash of the master key.
     *
     * @return the node's fingerprint as an integer.
     */
    public int getFingerPrint() {
        byte[] address = master.getAddressHash();
        return Ints.fromByteArray(address);
    }

    /**
     * Get the parent node's fingeprint.
     *
     * @return the parent node's fingerprint.
     */
    public int getParent() {
        return parent;
    }

    /**
     * Get the sequence into the parent node that this was generated at.
     *
     * @return the sequence into the parent node.
     */
    public int getSequence() {
        return sequence;
    }

    /**
     * Obtain whether or not the master key has private bits.
     *
     * @return true if the master key has private bits.
     */
    public boolean hasPrivate() {
        return master.hasPrivate();
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
        BIP0032Node that = (BIP0032Node) obj;
        return Objects.equal(depth, that.depth)
                && Objects.equal(parent, that.parent)
                && Objects.equal(sequence, that.sequence)
                && Objects.equal(master, that.master)
                && Arrays.equals(chainCode, that.chainCode);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(master, Arrays.hashCode(chainCode), depth, parent, sequence);
    }
}
