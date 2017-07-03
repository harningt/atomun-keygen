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

package us.eharning.atomun.keygen.path

import com.google.common.base.Preconditions

/**
 * Specialized version of BIP0032Path implementing BIP0044 specification.
 */
class BIP0044Path
/**
 * Construct a path from a sub-list of segments, validating that it is a valid BIP0044 sub-path.
 *
 * @param segments
 *         path segments source.
 * @param segmentsLength
 *         number of segments to use in path.
 */
@JvmOverloads
internal constructor(
        segments: IntArray,
        segmentsLength: Int = segments.size
) : BIP0032Path(segments, segmentsLength) {

    init {
        validate(this.segments, this.segments.size)
    }

    /**
     * Check whether or not the coin-type was set.

     * @return true if the coin-type is defined.
     */
    fun hasCoinType(): Boolean {
        return segments.size >= COIN_TYPE_INDEX
    }

    /**
     * Obtain the set coin-type value.

     * @return integer representing the coin-type.
     */
    val coinType: Int
        get() {
            check(hasCoinType(), { "Path does not contain coinType" })
            return segments[COIN_TYPE_INDEX]
        }

    /**
     * Check whether or not the account was set.

     * @return true if the account is defined.
     */
    fun hasAccount(): Boolean {
        return segments.size >= ACCOUNT_INDEX
    }

    /**
     * Obtain the account index.

     * @return integer representing the account index.
     */
    val account: Int
        get() {
            check(hasAccount(), { "Path does not contain account" })
            return 0x80000000.toInt().inv() and segments[ACCOUNT_INDEX]
        }

    /**
     * Check whether or not the chain was set.

     * @return true if the chain is defined.
     */
    fun hasChain(): Boolean {
        return segments.size >= CHAIN_INDEX
    }

    /**
     * Obtain the chain number.

     * @return integer representing the chain number.
     */
    val chain: Int
        get() {
            check(hasChain(), { "Path does not contain chain" })
            return segments[CHAIN_INDEX]
        }

    /**
     * Check whether or not the address index was set.

     * @return true if the address index is defined.
     */
    fun hasAddress(): Boolean {
        return segments.size >= ADDRESS_INDEX
    }

    /**
     * Obtain the address index.

     * @return integer representing the address index.
     */
    val address: Int
        get() {
            check(hasAddress(), { "Path does not contain address" })
            return segments[ADDRESS_INDEX]
        }

    /**
     * Builder for BIP0044 paths.
     */
    class Builder : BIP0032Path.Builder(0) {
        /* Bitset representing the set elements, any 'holes' are a problem */
        private var setElements = 0

        /**
         * Construct a BIP0044 path builder instance.
         */
        init {
            reserve(MAX_PATH_LENGTH)
            setSegment(PURPOSE_INDEX, BIP0044_PURPOSE)
        }

        /**
         * Set the coin-type.
         *
         * @param coinType
         *         coin-type value to set.
         *
         * @return self to permit chaining.
         */
        fun setCoinType(coinType: Int): Builder {
            setSegment(COIN_TYPE_INDEX, coinType)
            return this
        }

        /**
         * Set the account index.
         *
         * @param account
         *         account index to set.
         *
         * @return self to permit chaining.
         */
        fun setAccount(account: Int): Builder {
            setSegment(ACCOUNT_INDEX, account or HARDENED_FLAG)
            return this
        }

        /**
         * Set the chain number.
         *
         * @param chain
         *         chain number to set.
         *
         * @return self to permit chaining.
         */
        fun setChain(chain: Int): Builder {
            setSegment(CHAIN_INDEX, chain and INDEX_MASK)
            return this
        }

        /**
         * Set the address index.
         *
         * @param address
         *         address index to set.
         *
         * @return self to permit chaining.
         */
        fun setAddress(address: Int): Builder {
            setSegment(ADDRESS_INDEX, address and INDEX_MASK)
            return this
        }

        /**
         * Set the segment at the given index to the provided value.
         *
         * @param index
         *         offset to set the new value at.
         * @param segment
         *         value to store.
         */
        override fun setSegment(index: Int, segment: Int) {
            super.setSegment(index, segment)
            setElements = setElements or (1 shl index)
        }

        /**
         * Reset the segment list to empty, future calls must prepare the purpose properly.
         */
        override fun reset() {
            super.reset()
            setElements = 0
        }

        /**
         * Validate that this path is valid.
         *
         * @return self to permit chaining.
         */
        override fun validate(): Builder {
            /* "Slow" method because we only have 5 bits at most */
            var elementCheck = setElements
            while (elementCheck != 0) {
                /* Cannot have unset bits within valid range */
                Preconditions.checkState(elementCheck and 1 != 0)
                elementCheck = elementCheck shr 1
            }
            return this
        }

        /**
         * Construct the path from the contained segment data.
         *
         * @return finalized path from this builder.
         */
        override fun build(): BIP0044Path {
            validate()
            return BIP0044Path(segments, segmentsLength)
        }

        /**
         * Add a new segment to the builder.
         *
         * @param segment
         *         value to store.
         *
         * @return self to permit chaining.
         */
        override fun addSegment(segment: Int): Builder {
            super.addSegment(segment)

            /* Make sure the max path wasn't crossed */
            check(segmentsLength <= MAX_PATH_LENGTH, { "Path too long: $segmentsLength > $MAX_PATH_LENGTH" })

            return this
        }


        /**
         * Load a BIP0032-formatted string, resetting any prior configuration.
         *
         * @param path
         *         BIP0032-formatted sequence to load.
         *
         * @return self to permit chaining.
         */
        override fun loadBIP0032String(path: String): Builder {
            super.loadBIP0032String(path)

            /* Verify that the minimal requirement that the purpose be set to BIP0044 and not be too long */
            /* Loading a BIP0032 string is the only way the purpose can be broken
             * and path length broken.
             */
            BIP0044Path.validate(segments, segmentsLength)
            return this
        }
    }

    companion object {
        private val HARDENED_FLAG:Int = 0x80000000.toInt()
        private val INDEX_MASK:Int = 0x7FFFFFFF
        private val BIP0044_PURPOSE = getSegment(44, true)

        private val PURPOSE_INDEX = 0
        private val COIN_TYPE_INDEX = 1
        private val ACCOUNT_INDEX = 2
        private val CHAIN_INDEX = 3
        private val ADDRESS_INDEX = 4
        private val MAX_PATH_LENGTH = 5

        /**
         * Construct a path from a BIP0032-formatted string, validating that it is a valid BIP0044 sub-path.
         *
         * @param path
         *         BIP0032-formatted path.
         *
         * @return instance to operate on.
         */
        @JvmStatic
        fun fromBIP0032String(path: String): BIP0044Path {
            val builder = Builder()
            builder.loadBIP0032String(path)
            return builder.build()
        }

        /**
         * Construct a path from a BIP0032 path, validating that it is a valid BIP0044 sub-path.
         *
         * @param path
         *         BIP0032 path.
         *
         * @return instance to operate on.
         */
        @JvmStatic
        fun fromPath(path: BIP0032Path): BIP0044Path {
            if (path is BIP0044Path) {
                return path
            }
            return BIP0044Path(path.segments)
        }

        /**
         * Check if the given BIP0032Path is a valid BIP0044Path.
         *
         * @param path
         *         BIP0032 path.
         */
        @JvmStatic
        fun checkValidPath(path: BIP0032Path) {
            validate(path.segments, path.segments.size)
        }

        /**
         * Calculate the proper segment value based in the unsigned value and whether it should be a hardened index.
         *
         * @param value
         *         unsigned segment integer.
         * @param hardened
         *         whether or not the value is BIP0032-hardened.
         *
         * @return final calculated segment value.
         */
        private fun getSegment(value: Int, hardened: Boolean): Int {
            require(value > 0, { "Illegal segment value: $value <= 0" })
            return if (!hardened) value else HARDENED_FLAG or value
        }

        /**
         * Validate that this path is valid.
         *
         * @param segments
         *         array of segment values to validate.
         * @param segmentsLength
         *         length of valid elements in the segments array.
         */
        private fun validate(segments: IntArray, segmentsLength: Int) {
            require(segmentsLength <= MAX_PATH_LENGTH, { "Path too long: $segmentsLength > $MAX_PATH_LENGTH" })
            require(segmentsLength > PURPOSE_INDEX, { "Path too short: $segmentsLength < $PURPOSE_INDEX" })
            require(segments[PURPOSE_INDEX] == BIP0044_PURPOSE, { "Not a BIP0044 path: ${segments[PURPOSE_INDEX]} != $BIP0044_PURPOSE" })
        }
    }
}