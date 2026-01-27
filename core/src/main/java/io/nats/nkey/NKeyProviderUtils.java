// Copyright 2020-2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package io.nats.nkey;

import org.jspecify.annotations.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static io.nats.nkey.NKeyConstants.*;

/**
 * Provider Utils
 */
public abstract class NKeyProviderUtils {
    private NKeyProviderUtils() {} /* ensures cannot be constructed */

    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int MASK = 31;
    private static final int SHIFT = 5;

    // initialized in static initializer block
    private static final int[] BASE32_LOOKUP = new int[256];

    static {
        Arrays.fill(BASE32_LOOKUP, 0xFF);
        for (int i = 0; i < BASE32_CHARS.length(); i++) {
            int index = BASE32_CHARS.charAt(i) - '0';
            BASE32_LOOKUP[index] = i;
        }
    }

    /**
     * determine if the prefix is not a public prefix
     * @param prefix the prefix
     * @return true if the prefix is not public
     */
    public static boolean notValidPublicPrefixByte(int prefix) {
        return switch (prefix) {
            case PREFIX_BYTE_SERVER,
                 PREFIX_BYTE_CLUSTER,
                 PREFIX_BYTE_OPERATOR,
                 PREFIX_BYTE_ACCOUNT,
                 PREFIX_BYTE_USER -> false;
            default -> true;
        };
    }

    /**
     * remove padding from a base32 encoded character array
     * @param withPad the character array with padding
     * @return the character array without padding
     */
    public static char[] removePaddingAndClear(char[] withPad) {
        int i;
        for (i = withPad.length-1; i >= 0; i--) {
            if (withPad[i] != '=') {
                break;
            }
        }
        char[] withoutPad = new char[i+1];
        System.arraycopy(withPad, 0, withoutPad, 0, withoutPad.length);

        Arrays.fill(withPad, '\0');

        return withoutPad;
    }

    /**
     * Encode to nkey format
     * @param type the type
     * @param src the seed bytes
     * @return the encoded characters
     */
    public static char[] nkeyEncode(NKeyType type, byte[] src){
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();

            bytes.write(type.prefix);
            bytes.write(src);

            int crc = crc16(bytes.toByteArray());
            byte[] littleEndian = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) crc).array();

            bytes.write(littleEndian);

            char[] withPad = base32Encode(bytes.toByteArray());
            return removePaddingAndClear(withPad);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encode the seed
     * @param type the type
     * @param src the seed bytes
     * @return the encoded characters
     */
    public static char[] encodeSeed(NKeyType type, byte[] src) {
        if (src.length != ED25519_PRIVATE_KEYSIZE && src.length != ED25519_SEED_SIZE) {
            throw new IllegalArgumentException("Source is not the correct size for an ED25519 seed");
        }

        try {
            // In order to make this human printable for both bytes, we need to do a little
            // bit manipulation to setup for base32 encoding which takes 5 bits at a time.
            int b1 = PREFIX_BYTE_SEED | (type.prefix >> 5);
            int b2 = (type.prefix & 31) << 3; // 31 = 00011111

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();

            bytes.write(b1);
            bytes.write(b2);
            bytes.write(src);

            int crc = crc16(bytes.toByteArray());
            byte[] littleEndian = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) crc).array();

            bytes.write(littleEndian);

            char[] withPad = base32Encode(bytes.toByteArray());
            return removePaddingAndClear(withPad);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decode the encoded characters from NKey format
     * @param src the encoded characters
     * @return the decoded characters
     */
    public static byte[] nkeyDecode(char[] src) {
        byte[] raw = base32Decode(src);

        if (raw.length < 4) {
            throw new IllegalArgumentException("Invalid encoding for source string");
        }

        byte[] crcBytes = Arrays.copyOfRange(raw, raw.length - 2, raw.length);
        byte[] dataBytes = Arrays.copyOfRange(raw, 0, raw.length - 2);

        int crc = ByteBuffer.wrap(crcBytes).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int actual = crc16(dataBytes);

        if (actual != crc) {
            throw new IllegalArgumentException("CRC is invalid");
        }

        return dataBytes;
    }

    /**
     * Decode the encoded characters from NKey format expecting a specific type
     * @param expectedType the expected type of the NKey
     * @param src the encoded characters
     * @return the decoded characters
     */
    public static byte @NonNull [] nkeyDecode(NKeyType expectedType, char[] src) {
        byte[] raw = nkeyDecode(src);
        byte[] dataBytes = Arrays.copyOfRange(raw, 1, raw.length);
        NKeyType type = NKeyType.fromPrefix(raw[0] & 0xFF);
        if (type == null) {
            throw new IllegalArgumentException("Unknown prefix");
        }
        if (type != expectedType) {
            throw new IllegalArgumentException("Unexpected NKeyType");
        }
        return dataBytes;
    }

    /**
     * Decode the seed
     * @param seed the encoded seed characters
     * @return the decoded bytes
     */
    public static NKeyDecodedSeed decodeSeed(char[] seed) {
        byte[] raw = nkeyDecode(seed);

        // Need to do the reverse here to get back to internal representation.
        int b1 = raw[0] & 248; // 248 = 11111000
        int b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3); // 7 = 00000111

        if (b1 != PREFIX_BYTE_SEED) {
            throw new IllegalArgumentException("Invalid encoding");
        }

        if (notValidPublicPrefixByte(b2)) {
            throw new IllegalArgumentException("Invalid encoded prefix byte");
        }

        byte[] dataBytes = Arrays.copyOfRange(raw, 2, raw.length);
        return new NKeyDecodedSeed(b2, dataBytes);
    }

    /**
     * Calculate a crc16
     * @param bytes the bytes to use to calculate
     * @return the crc
     */
    public static int crc16(byte[] bytes) {
        int crc = 0;

        for (byte b : bytes) {
            crc = ((crc << 8) & 0xffff) ^ CRC_16_TABLE[((crc >> 8) ^ (b & 0xFF)) & 0x00FF];
        }

        return crc;
    }

    /**
     * Base 32 Encode a byte array
     * @see <a href="http://en.wikipedia.org/wiki/Base_32">wikipedia Base 32</a>
     * @param input the byte array
     * @return the base32 encoded character array
     */
    public static char[] base32Encode(final byte[] input) {
        int last = input.length;
        char[] charBuff = new char[(last + 7) * 8 / SHIFT];
        int offset = 0;
        int buffer = input[offset++];
        int bitsLeft = 8;
        int i = 0;

        while (bitsLeft > 0 || offset < last) {
            if (bitsLeft < SHIFT) {
                if (offset < last) {
                    buffer <<= 8;
                    buffer |= (input[offset++] & 0xff);
                    bitsLeft += 8;
                } else {
                    int pad = SHIFT - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            int index = MASK & (buffer >> (bitsLeft - SHIFT));
            bitsLeft -= SHIFT;
            charBuff[i] = BASE32_CHARS.charAt(index);
            i++;
        }

        int nonBlank;

        for (nonBlank=charBuff.length-1;nonBlank>=0;nonBlank--) {
            if (charBuff[nonBlank] != 0) {
                break;
            }
        }

        char[] retVal = new char[nonBlank+1];

        System.arraycopy(charBuff, 0, retVal, 0, retVal.length);

        Arrays.fill(charBuff, '\0');

        return retVal;
    }

    /**
     * Base 32 Decode a character array
     * @see <a href="http://en.wikipedia.org/wiki/Base_32">wikipedia Base 32</a>
     * @param input the character array
     * @return the decoded byte array
     */
    public static byte[] base32Decode(final char[] input) {
        byte[] bytes = new byte[input.length * SHIFT / 8];
        int buffer = 0;
        int next = 0;
        int bitsLeft = 0;

        for (char value : input) {
            int lookup = value - '0';

            if (lookup < 0 || lookup >= BASE32_LOOKUP.length) {
                continue;
            }

            int c = BASE32_LOOKUP[lookup];
            buffer <<= SHIFT;
            buffer |= c & MASK;
            bitsLeft += SHIFT;
            if (bitsLeft >= 8) {
                bytes[next++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        return bytes;
    }
}
