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

package us.eharning.atomun.keygen.path;

import com.google.common.base.Preconditions;

/**
 * Specialized version of BIP0032Path implementing BIP0044 specification.
 */
public class BIP0044Path extends BIP0032Path {
    private static final int BIP0044_PURPOSE = getSegment(44, true);

    private static final int PURPOSE_INDEX = 0;
    private static final int COIN_TYPE_INDEX = 1;
    private static final int ACCOUNT_INDEX = 2;
    private static final int CHAIN_INDEX = 3;
    private static final int ADDRESS_INDEX = 4;
    private static final int MAX_PATH_LENGTH = 5;

    /**
     * Construct a path from a list of segments, validating that it is a valid BIP0044 sub-path.
     *
     * @param segments
     *         path segments.
     */
    BIP0044Path(int[] segments) {
        this(segments, segments.length);
    }

    /**
     * Construct a path from a sub-list of segments, validating that it is a valid BIP0044 sub-path.
     *
     * @param segments
     *         path segments source.
     * @param segmentsLength
     *         number of segments to use in path.
     */
    BIP0044Path(int[] segments, int segmentsLength) {
        super(segments, segmentsLength);
        validate(this.segments, this.segments.length);
    }

    /**
     * Construct a path from a BIP0032-formatted string, validating that it is a valid BIP0044 sub-path.
     *
     * @param path
     *         BIP0032-formatted path.
     *
     * @return instance to operate on.
     */
    public static BIP0044Path fromBIP0032String(String path) {
        Builder builder = new Builder();
        builder.loadBIP0032String(path);
        return builder.build();
    }

    /**
     * Construct a path from a BIP0032 path, validating that it is a valid BIP0044 sub-path.
     *
     * @param path
     *         BIP0032 path.
     *
     * @return instance to operate on.
     */
    public static BIP0044Path fromPath(BIP0032Path path) {
        return new BIP0044Path(path.segments);
    }

    /**
     * Check if the given BIP0032Path is a valid BIP0044Path.
     *
     * @param path
     *         BIP0032 path.
     */
    public static void checkValidPath(BIP0032Path path) {
        validate(path.segments, path.segments.length);
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
    private static int getSegment(int value, boolean hardened) {
        Preconditions.checkArgument(value > 0, "Illegal segment value");
        return !hardened ? value : (0x80000000 | value);
    }

    /**
     * Validate that this path is valid.
     *
     * @param segments
     *         array of segment values to validate.
     * @param segmentsLength
     *         length of valid elements in the segments array.
     */
    private static void validate(int[] segments, int segmentsLength) {
        Preconditions.checkArgument(segmentsLength <= MAX_PATH_LENGTH, "Path too long");
        Preconditions.checkArgument(segmentsLength > PURPOSE_INDEX, "Path too short");
        Preconditions.checkArgument(segments[PURPOSE_INDEX] == BIP0044_PURPOSE, "Not a BIP0044 path");
    }

    /**
     * Check whether or not the coin-type was set.
     *
     * @return true if the coin-type is defined.
     */
    public boolean hasCoinType() {
        return segments.length >= COIN_TYPE_INDEX;
    }

    /**
     * Obtain the set coin-type value.
     *
     * @return integer representing the coin-type.
     */
    public int getCoinType() {
        Preconditions.checkState(hasCoinType(), "Path does not contain coinType");
        return segments[COIN_TYPE_INDEX];
    }

    /**
     * Check whether or not the account was set.
     *
     * @return true if the account is defined.
     */
    public boolean hasAccount() {
        return segments.length >= ACCOUNT_INDEX;
    }

    /**
     * Obtain the account index.
     *
     * @return integer representing the account index.
     */
    public int getAccount() {
        Preconditions.checkState(hasAccount(), "Path does not contain account");
        return (~0x80000000) & segments[ACCOUNT_INDEX];
    }

    /**
     * Check whether or not the chain was set.
     *
     * @return true if the chain is defined.
     */
    public boolean hasChain() {
        return segments.length >= CHAIN_INDEX;
    }

    /**
     * Obtain the chain number.
     *
     * @return integer representing the chain number.
     */
    public int getChain() {
        Preconditions.checkState(hasChain(), "Path does not contain chain");
        return segments[CHAIN_INDEX];
    }

    /**
     * Check whether or not the address index was set.
     *
     * @return true if the address index is defined.
     */
    public boolean hasAddress() {
        return segments.length >= ADDRESS_INDEX;
    }

    /**
     * Obtain the address index.
     *
     * @return integer representing the address index.
     */
    public int getAddress() {
        Preconditions.checkState(hasAddress(), "Path does not contain address");
        return segments[ADDRESS_INDEX];
    }

    /**
     * Builder for BIP0044 paths.
     */
    public static class Builder extends BIP0032Path.Builder {
        /* Bitset representing the set elements, any 'holes' are a problem */
        private int setElements = 0;

        /**
         * Construct a BIP0044 path builder instance.
         */
        public Builder() {
            super(0);
            reserve(MAX_PATH_LENGTH);
            setSegment(PURPOSE_INDEX, BIP0044_PURPOSE);
        }

        /**
         * Set the coin-type.
         *
         * @param coinType
         *         coin-type value to set.
         *
         * @return self to permit chaining.
         */
        public Builder setCoinType(int coinType) {
            setSegment(COIN_TYPE_INDEX, coinType);
            return this;
        }

        /**
         * Set the account index.
         *
         * @param account
         *         account index to set.
         *
         * @return self to permit chaining.
         */
        public Builder setAccount(int account) {
            setSegment(ACCOUNT_INDEX, account | 0x80000000);
            return this;
        }

        /**
         * Set the chain number.
         *
         * @param chain
         *         chain number to set.
         *
         * @return self to permit chaining.
         */
        public Builder setChain(int chain) {
            setSegment(CHAIN_INDEX, chain & (~0x80000000));
            return this;
        }

        /**
         * Set the address index.
         *
         * @param address
         *         address index to set.
         *
         * @return self to permit chaining.
         */
        public Builder setAddress(int address) {
            setSegment(ADDRESS_INDEX, address & (~0x80000000));
            return this;
        }

        /**
         * Set the segment at the given index to the provided value.
         *
         * @param index
         *         offset to set the new value at.
         * @param segment
         *         value to store.
         */
        @Override
        protected void setSegment(int index, int segment) {
            super.setSegment(index, segment);
            setElements |= 1 << index;
        }

        /**
         * Reset the segment list to empty, future calls must prepare the purpose properly.
         */
        @Override
        protected void reset() {
            super.reset();
            setElements = 0;
        }

        /**
         * Validate that this path is valid.
         *
         * @return self to permit chaining.
         */
        @Override
        public Builder validate() {
            /* "Slow" method because we only have 5 bits at most */
            int elementCheck = setElements;
            while (elementCheck != 0) {
                /* Cannot have unset bits within valid range */
                Preconditions.checkState((elementCheck & 1) != 0);
                elementCheck >>= 1;
            }
            return this;
        }

        /**
         * Construct the path from the contained segment data.
         *
         * @return finalized path from this builder.
         */
        @Override
        public BIP0044Path build() {
            validate();
            return new BIP0044Path(segments, segmentsLength);
        }

        /**
         * Add a new segment to the builder.
         *
         * @param segment
         *         value to store.
         *
         * @return self to permit chaining.
         */
        @Override
        public Builder addSegment(int segment) {
            super.addSegment(segment);

            /* Make sure the max path wasn't crossed */
            Preconditions.checkArgument(segmentsLength <= MAX_PATH_LENGTH, "Path too long");

            return this;
        }


        /**
         * Load a BIP0032-formatted string, resetting any prior configuration.
         *
         * @param path
         *         BIP0032-formatted sequence to load.
         *
         * @return self to permit chaining.
         */
        @Override
        public Builder loadBIP0032String(String path) {
            super.loadBIP0032String(path);

            /* Verify that the minimal requirement that the purpose be set to BIP0044 and not be too long */
            /* Loading a BIP0032 string is the only way the purpose can be broken
             * and path length broken.
             */
            BIP0044Path.validate(segments, segmentsLength);
            return this;
        }
    }
}
