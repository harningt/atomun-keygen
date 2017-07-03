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

import com.google.common.base.Splitter
import com.google.common.primitives.Ints
import us.eharning.atomun.keygen.PathParameter

/**
 * Generic BIP0032 path instance.
 */
open class BIP0032Path
/**
 * Construct a path from a sub-list of segments.
 *
 * @param segments
 *         path segments to take ownership of.
 * @param segmentsLength
 *         number of segments to use in path.
 */
@JvmOverloads
internal constructor(
        segments: IntArray,
        segmentsLength: Int = segments.size
) : Iterable<Int>, PathParameter {
    @JvmField
    val segments = segments.copyOf(segmentsLength)

    /**
     * Returns an iterator over elements of type `T`.
     *
     * @return an Iterator.
     */
    override fun iterator(): Iterator<Int> {
        return segments.iterator()
    }

    /**
     * Convert this instance to a string representation.
     *
     * @return BIP0032-formatted string
     */
    override fun toString(): String {
        val builder = StringBuilder()
        builder.append("m")
        for (segment in segments) {
            builder.append('/')
            if (0 != segment and HARDENED_FLAG) {
                builder.append(segment and INDEX_MASK)
                builder.append('\'')
            } else {
                builder.append(segment)
            }
        }
        return builder.toString()
    }

    /**
     * Builder of paths.
     */
    open class Builder {
        private val padding: Int
        @JvmField /* No get/set - avoid findbugs issues */
        internal var segments = EMPTY_ARRAY
        internal var segmentsLength = 0

        /**
         * Construct a BIP0032 path builder instance.
         */
        constructor() {
            padding = DEFAULT_PADDING
        }

        /**
         * Construct a BIP0032 path builder instance with a specific padding size.
         *
         * @param padding
         *         number of padding elements for the segment array when re-allocating.
         */
        protected constructor(padding: Int) {
            this.padding = padding
        }

        /**
         * Construct the path from the contained segment data.
         *
         * @return finalized path from this builder.
         */
        open fun build(): BIP0032Path {
            validate()
            return BIP0032Path(segments, segmentsLength)
        }

        /**
         * Validate that this path is valid.
         *
         * @return self to permit chaining.
         */
        open fun validate(): Builder {
            /* No-op for 'plain' paths */
            return this
        }

        /**
         * Ensure that the segments array has at least 'length' slots.
         *
         * @param length
         *         minimum number of slots to reserve space for.
         */
        protected fun reserve(length: Int) {
            segments = Ints.ensureCapacity(segments, length, padding)
        }

        /**
         * Set the segment at the given index to the provided value.
         *
         * @param index
         *         offset to set the new value at.
         * @param segment
         *         value to store.
         */
        protected open fun setSegment(index: Int, segment: Int) {
            segments[index] = segment
            /* Autogrow 'valid' range, may leave holes */
            if (segmentsLength <= index) {
                segmentsLength = index + 1
            }
        }

        /**
         * Reset the segment list to empty.
         */
        protected open fun reset() {
            segmentsLength = 0
        }

        /**
         * Add a new segment to the builder.
         *
         * @param segment
         *         value to store.
         *
         * @return self to permit chaining.
         */
        open fun addSegment(segment: Int): Builder {
            reserve(segmentsLength + 1)
            setSegment(segmentsLength, segment)
            return this
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
        fun addSegment(segment: Int, isHardened: Boolean): Builder {
            require(segment == segment and INDEX_MASK)
            val segmentValue: Int
            if (isHardened) {
                segmentValue = segment or HARDENED_FLAG
            } else {
                segmentValue = segment
            }
            reserve(segmentsLength + 1)
            setSegment(segmentsLength, segmentValue)
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
        open fun loadBIP0032String(path: String): Builder {
            reset()
            var isFirst = true
            for (item in Splitter.on('/').split(path)) {
                if (isFirst) {
                    require(item == "m")
                    isFirst = false
                    continue
                }
                val segment: Int
                if (item.endsWith("'")) {
                    segment = HARDENED_FLAG or item.substring(0, item.length - 1).toInt(10)
                } else {
                    segment = Integer.parseInt(item, 10)
                }
                addSegment(segment)
            }
            return this
        }

        companion object {
            private val EMPTY_ARRAY = IntArray(0)
            private val DEFAULT_PADDING = 5
        }
    }

    companion object {
        private val HARDENED_FLAG:Int = 0x80000000.toInt()
        private val INDEX_MASK:Int = 0x7FFFFFFF

        /**
         * Construct a path from a sequence of integers as segments.
         *
         * @param segments
         *         path segments.
         *
         * @return instance to operate on.
         */
        @JvmStatic
        fun fromSegments(vararg segments: Int): BIP0032Path {
            return BIP0032Path(segments.copyOf())
        }

        /**
         * Construct a path from a BIP0032-formatted string.
         *
         * @param path
         *         BIP0032-formatted path.
         *
         * @return instance to operate on.
         */
        @JvmStatic
        fun fromBIP0032String(path: String): BIP0032Path {
            val builder = BIP0032Path.Builder()
            builder.loadBIP0032String(path)
            return builder.build()
        }
    }
}
