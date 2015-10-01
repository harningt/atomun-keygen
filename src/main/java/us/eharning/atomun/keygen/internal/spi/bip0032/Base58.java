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

import static java.util.Arrays.copyOfRange;

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import us.eharning.atomun.keygen.base.ValidationException;

import java.math.BigInteger;
import java.util.Arrays;
import javax.annotation.Nullable;

/**
 * Utility class to perform Base58 transformations.
 */
final class Base58 {
    private static final Converter<byte[], String> CODEC = new ByteArrayBase58Codec();

    /**
     * Prevent construction as this is a static utility class.
     */
    private Base58() {
    }

    /**
     * Encode the data directly to Base58.
     *
     * @param data
     *         bytes to encode.
     *
     * @return base58-encoded string.
     */
    public static String encode(byte[] data) {
        return CODEC.convert(data);
    }

    /**
     * Encode the data to Base58 with a prefixed 4-byte checksum using SHA-256.
     *
     * @param data
     *         bytes to encode.
     *
     * @return Base58+checksum-encoded string.
     */
    public static String encodeWithChecksum(byte[] data) {
        byte[] cs = Hash.hash(data);
        byte[] extended = new byte[data.length + 4];
        System.arraycopy(data, 0, extended, 0, data.length);
        System.arraycopy(cs, 0, extended, data.length, 4);
        return CODEC.convert(extended);
    }

    /**
     * Decode a Base58-encoded string.
     *
     * @param base58
     *         Base58-encoded string.
     *
     * @return bytes represented by string.
     */
    public static byte[] decode(String base58) {
        return CODEC.reverse().convert(base58);
    }

    /**
     * Decode a Base58+checksum-encoded string, verifying and stripping the 4-byte checksum.
     *
     * @param base58
     *         Base58+checksum-encoded string.
     *
     * @return bytes represented by string.
     */
    public static byte[] decodeWithChecksum(String base58) throws ValidationException {
        byte[] bytes = Base58.decode(base58);
        if (bytes.length < 4) {
            throw new ValidationException("Input string too short to contain checksum");
        }
        byte[] checksum = new byte[4];
        System.arraycopy(bytes, bytes.length - 4, checksum, 0, 4);
        byte[] data = new byte[bytes.length - 4];
        System.arraycopy(bytes, 0, data, 0, bytes.length - 4);
        byte[] calculatedChecksum = new byte[4];
        System.arraycopy(Hash.hash(data), 0, calculatedChecksum, 0, 4);
        if (Arrays.equals(checksum, calculatedChecksum)) {
            return data;
        }
        throw new ValidationException("Checksum mismatch");
    }

    /**
     * Utility class implementing the Base58-codec using BigIntegers.
     */
    @SuppressWarnings("unused")
    @SuppressFBWarnings({"HE_INHERITS_EQUALS_USE_HASHCODE"})
    private static class BigIntegerBase58Codec extends Converter<byte[], String> {
        private static final char[] b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
        private static final int[] r58 = new int[256];

        static {
            for (int i = 0; i < 256; ++i) {
                r58[i] = -1;
            }
            for (int i = 0; i < b58.length; ++i) {
                r58[b58[i]] = i;
            }
        }

        /**
         * Returns a representation of {@code a} as an instance of type {@code B}. If {@code a} cannot be
         * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
         *
         * @param bytes
         *         the instance to convert; will never be null
         *
         * @return the converted instance; <b>must not</b> be null
         */
        @Override
        protected String doForward(@Nullable byte[] bytes) {
            assert (null != bytes);
            if (bytes.length == 0) {
                return "";
            }
            int leadingZeroes = 0;
            while (leadingZeroes < bytes.length && bytes[leadingZeroes] == 0) {
                ++leadingZeroes;
            }
            StringBuilder buffer = new StringBuilder();
            BigInteger value = new BigInteger(1, bytes);
            while (value.compareTo(BigInteger.ZERO) > 0) {
                BigInteger[] result = value.divideAndRemainder(BigInteger.valueOf(58));
                value = result[0];
                char digit = b58[result[1].intValue()];
                buffer.append(digit);
            }
            while (leadingZeroes > 0) {
                --leadingZeroes;
                buffer.append("1");
            }
            return buffer.reverse().toString();
        }

        /**
         * Performs a reverse conversion of string-to-bytes.
         *
         * @param str
         *         the instance to convert; will never be null
         *
         * @return the converted instance; <b>must not</b> be null
         */
        @Override
        protected byte[] doBackward(@Nullable String str) {
            assert (null != str);
            try {
                boolean leading = true;
                int leadingZeroes = 0;
                BigInteger value = BigInteger.ZERO;
                for (char c : str.toCharArray()) {
                    if (leading && c == '1') {
                        ++leadingZeroes;
                    } else {
                        leading = false;
                        value = value.multiply(BigInteger.valueOf(58));
                        value = value.add(BigInteger.valueOf(r58[c]));
                    }
                }
                byte[] encoded = value.toByteArray();
                if (encoded[0] == 0) {
                    if (leadingZeroes > 0) {
                        --leadingZeroes;
                    } else {
                        byte[] encodedBytes = new byte[encoded.length - 1];
                        System.arraycopy(encoded, 1, encodedBytes, 0, encodedBytes.length);
                        encoded = encodedBytes;
                    }
                }
                byte[] result = new byte[encoded.length + leadingZeroes];
                System.arraycopy(encoded, 0, result, leadingZeroes, encoded.length);
                return result;
            } catch (ArrayIndexOutOfBoundsException e) {
                throw new IllegalArgumentException("Invalid character in address");
            }
        }
    }

    /**
     * Utility class implementing the Base58-codec using a byte array.
     */
    @SuppressWarnings("unused")
    @SuppressFBWarnings({"HE_INHERITS_EQUALS_USE_HASHCODE"})
    private static class ByteArrayBase58Codec extends Converter<byte[], String> {
        public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
        private static final int[] INDEXES = new int[128];

        static {
            for (int i = 0; i < INDEXES.length; i++) {
                INDEXES[i] = -1;
            }
            for (int i = 0; i < ALPHABET.length; i++) {
                INDEXES[ALPHABET[i]] = i;
            }
        }

        /**
         * Perform division modulo 58.
         *
         * @param number
         *         byte array representing the large number to divide - modified in place to have the division result.
         * @param startAt
         *         index to consider the beginning of the number.
         *
         * @return the result of number % 58.
         * <p>
         * NOTE: number -> number / 58, returns number % 58.
         * </p>
         */
        private static byte divmod58(byte[] number, int startAt) {
            int remainder = 0;
            for (int i = startAt; i < number.length; i++) {
                int digit256 = (int) number[i] & 0xFF;
                int temp = remainder * 256 + digit256;
                number[i] = (byte) (temp / 58);
                remainder = temp % 58;
            }
            return (byte) remainder;
        }

        /**
         * Perform division modulo 256.
         *
         * @param number58
         *         byte array representing the large number to divide - modified in place to have the division result.
         * @param startAt
         *         index to consider the beginning of the number.
         *
         * @return the result of number % 256.
         * <p>
         * NOTE: number -> number / 256, returns number % 256.
         * </p>
         */
        private static byte divmod256(byte[] number58, int startAt) {
            int remainder = 0;
            for (int i = startAt; i < number58.length; i++) {
                int digit58 = (int) number58[i] & 0xFF;
                int temp = remainder * 58 + digit58;
                number58[i] = (byte) (temp / 256);
                remainder = temp % 256;
            }
            return (byte) remainder;
        }

        /**
         * Returns a representation of {@code a} as an instance of type {@code B}. If {@code a} cannot be
         * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
         *
         * @param input
         *         the instance to convert; will never be null
         *
         * @return the converted instance; <b>must not</b> be null
         */
        @Override
        protected String doForward(@Nullable byte[] input) {
            assert (null != input);
            if (input.length == 0) {
                return "";
            }
            input = copyOfRange(input, 0, input.length);
            // Count leading zeroes.
            int zeroCount = 0;
            while (zeroCount < input.length && input[zeroCount] == 0) {
                ++zeroCount;
            }
            // The actual encoding.
            byte[] temp = new byte[input.length * 2];
            int offset = temp.length;
            int startAt = zeroCount;
            while (startAt < input.length) {
                byte mod = divmod58(input, startAt);
                if (input[startAt] == 0) {
                    ++startAt;
                }
                temp[--offset] = (byte) ALPHABET[mod];
            }
            // Strip extra '1' if there are some after decoding.
            while (offset < temp.length && temp[offset] == ALPHABET[0]) {
                ++offset;
            }
            // Add as many leading '1' as there were leading zeros.
            while (--zeroCount >= 0) {
                temp[--offset] = (byte) ALPHABET[0];
            }
            byte[] output = copyOfRange(temp, offset, temp.length);
            return new String(output, Charsets.US_ASCII);
        }

        /**
         * Returns a representation of {@code b} as an instance of type {@code A}. If {@code b} cannot be
         * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
         *
         * @param input
         *         the instance to convert; will never be null
         *
         * @return the converted instance; <b>must not</b> be null
         */
        @Override
        protected byte[] doBackward(@Nullable String input) {
            assert (null != input);
            if (input.length() == 0) {
                return new byte[0];
            }
            byte[] input58 = new byte[input.length()];
            // Transform the String to a base58 byte sequence
            for (int i = 0; i < input.length(); ++i) {
                char inputChar = input.charAt(i);
                int digit58 = -1;
                if (inputChar < 128) {
                    digit58 = INDEXES[inputChar];
                }
                if (digit58 < 0) {
                    throw new IllegalArgumentException("Illegal character " + inputChar + " at " + i);
                }
                input58[i] = (byte) digit58;
            }
            // Count leading zeroes
            int zeroCount = 0;
            while (zeroCount < input58.length && input58[zeroCount] == 0) {
                ++zeroCount;
            }
            // The encoding
            byte[] temp = new byte[input.length()];
            int offset = temp.length;
            int startAt = zeroCount;
            while (startAt < input58.length) {
                byte mod = divmod256(input58, startAt);
                if (input58[startAt] == 0) {
                    ++startAt;
                }
                temp[--offset] = mod;
            }
            // Do no add extra leading zeroes, move offset to first non null byte.
            while (offset < temp.length && temp[offset] == 0) {
                ++offset;
            }
            return copyOfRange(temp, offset - zeroCount, temp.length);
        }
    }
}
