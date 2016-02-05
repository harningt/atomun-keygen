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
import com.google.common.base.Splitter;
import com.google.common.primitives.Ints;
import us.eharning.atomun.keygen.PathParameter;

import java.util.Arrays;
import java.util.Iterator;

/**
 * Generic BIP0032 path instance.
 */
public class BIP0032Path implements Iterable<Integer>, PathParameter {
    protected final int[] segments;

    /**
     * Construct a path from a list of segments.
     *
     * @param segments
     *         path segments.
     */
    BIP0032Path(int[] segments) {
        this(segments, segments.length);
    }

    /**
     * Construct a path from a sub-list of segments.
     *
     * @param segments
     *         path segments source.
     * @param segmentsLength
     *         number of segments to use in path.
     */
    BIP0032Path(int[] segments, int segmentsLength) {
        this.segments = Arrays.copyOf(segments, segmentsLength);
    }

    /**
     * Construct a path from a sequence of integers as segments.
     *
     * @param segments
     *         path segments.
     *
     * @return instance to operate on.
     */
    public static BIP0032Path fromSegments(int... segments) {
        return new BIP0032Path(segments);
    }

    /**
     * Construct a path from a BIP0032-formatted string.
     *
     * @param path
     *         BIP0032-formatted path.
     *
     * @return instance to operate on.
     */
    public static BIP0032Path fromBIP0032String(String path) {
        BIP0032Path.Builder builder = new BIP0032Path.Builder();
        builder.loadBIP0032String(path);
        return builder.build();
    }

    /**
     * Returns an iterator over elements of type {@code T}.
     *
     * @return an Iterator.
     */
    @Override
    public Iterator<Integer> iterator() {
        return Ints.asList(segments).iterator();
    }

    /**
     * Convert this instance to a string representation.
     *
     * @return BIP0032-formatted string
     */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("m");
        for (int segment : segments) {
            builder.append('/');
            if (0 != (segment & 0x80000000)) {
                builder.append(segment & 0x7FFFFFFF);
                builder.append('\'');
            } else {
                builder.append(segment);
            }
        }
        return builder.toString();
    }

    /**
     * Builder of paths.
     */
    public static class Builder {
        private static final int[] EMPTY_ARRAY = new int[0];
        private static final int DEFAULT_PADDING = 5;

        private final int padding;
        int[] segments = EMPTY_ARRAY;
        int segmentsLength = 0;

        /**
         * Construct a BIP0032 path builder instance.
         */
        public Builder() {
            padding = DEFAULT_PADDING;
        }

        /**
         * Construct a BIP0032 path builder instance with a specific padding size.
         *
         * @param padding
         *         number of padding elements for the segment array when re-allocating.
         */
        protected Builder(int padding) {
            this.padding = padding;
        }

        /**
         * Construct the path from the contained segment data.
         *
         * @return finalized path from this builder.
         */
        public BIP0032Path build() {
            validate();
            return new BIP0032Path(segments, segmentsLength);
        }

        /**
         * Validate that this path is valid.
         *
         * @return self to permit chaining.
         */
        public Builder validate() {
            /* No-op for 'plain' paths */
            return this;
        }

        /**
         * Ensure that the segments array has at least 'length' slots.
         *
         * @param length
         *         minimum number of slots to reserve space for.
         */
        protected void reserve(int length) {
            segments = Ints.ensureCapacity(segments, length, padding);
        }

        /**
         * Set the segment at the given index to the provided value.
         *
         * @param index
         *         offset to set the new value at.
         * @param segment
         *         value to store.
         */
        protected void setSegment(int index, int segment) {
            Preconditions.checkPositionIndex(index, segments.length);
            segments[index] = segment;
            /* Autogrow 'valid' range, may leave holes */
            if (segmentsLength <= index) {
                segmentsLength = index + 1;
            }
        }

        /**
         * Reset the segment list to empty.
         */
        protected void reset() {
            segmentsLength = 0;
        }

        /**
         * Add a new segment to the builder.
         *
         * @param segment
         *         value to store.
         *
         * @return self to permit chaining.
         */
        public Builder addSegment(int segment) {
            reserve(segmentsLength + 1);
            setSegment(segmentsLength, segment);
            return this;
        }

        /**
         * Add a new segment to the builder.
         *
         * @param segment
         *         value to store.
         * @param isHardened
         *         whether or not the value-to-be-stored should be set as a hardened node.
         *
         * @return self to permit chaining.
         */
        public Builder addSegment(int segment, boolean isHardened) {
            assert segment == (segment & ~0x80000000);
            segment = (segment & ~0x80000000);
            if (isHardened) {
                segment |= 0x80000000;
            }
            reserve(segmentsLength + 1);
            setSegment(segmentsLength, segment);
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
        public Builder loadBIP0032String(String path) {
            reset();
            boolean isFirst = true;
            for (String item : Splitter.on('/').split(path)) {
                if (isFirst) {
                    Preconditions.checkArgument(item.equals("m"));
                    isFirst = false;
                    continue;
                }
                int segment;
                if (item.endsWith("'")) {
                    segment = 0x80000000 | Integer.parseInt(item.substring(0, item.length() - 1), 10);
                } else {
                    segment = Integer.parseInt(item, 10);
                }
                addSegment(segment);
            }
            return this;
        }
    }
}
