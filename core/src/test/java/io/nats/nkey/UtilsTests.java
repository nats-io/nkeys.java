// Copyright 2020-2024 The NATS Authors
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

import io.ResourceUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static io.nats.nkey.NKeyConstants.*;
import static io.nats.nkey.NKeyInternalUtils.*;
import static io.nats.nkey.NKeyUtils.getProvider;
import static org.junit.jupiter.api.Assertions.*;

public class UtilsTests {
    @Test
    public void testCRC16() {
        // Example inputs and outputs from around the web
        byte[][] inputs = {
            {},
            "abc".getBytes(StandardCharsets.US_ASCII),
            "ABC".getBytes(StandardCharsets.US_ASCII),
            "This is a string".getBytes(StandardCharsets.US_ASCII),
            "123456789".getBytes(StandardCharsets.US_ASCII),
            "abcdefghijklmnopqrstuvwxyz0123456789".getBytes(StandardCharsets.US_ASCII),
            {(byte) 0x7F},
            {(byte) 0x80},
            {(byte) 0xFF},
            {0x0, 0x1, 0x7D, 0x7E, (byte) 0x7F, (byte) 0x80, (byte) 0xFE, (byte) 0xFF}
        };

        int[] expected = {
            0x0, // ""
            0x9DD6, // "abc"
            0x3994, // "ABC"
            0x21E3, // "This is a string"
            0x31C3, // "123456789"
            0xCBDE, // "abcdefghijklmnopqrstuvwxyz0123456789"
            0x8F78, // 0x7F
            0x9188, // 0x80
            0x1EF0, // 0xFF
            0xE26F, // {0x0,0x1,0x7D,0x7E, 0x7F, 0x80, 0xFE, 0xFF}
        };

        for (int i = 0; i < inputs.length; i++) {
            byte[] input = inputs[i];
            int crc = expected[i];
            int actual = crc16(input);
            assertEquals(crc, actual, String.format("CRC for \"%s\", should be 0x%08X but was 0x%08X", Arrays.toString(input), crc, actual));
        }
    }

    @Test
    public void testBase32() {
        List<String> inputs = ResourceUtils.resourceAsLines("utf8-test-strings.txt");

        for (String expected : inputs) {
            byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
            char[] encoded = base32Encode(expectedBytes);
            byte[] decoded = base32Decode(encoded);
            assertArrayEquals(expectedBytes, decoded);
            String test = new String(decoded, StandardCharsets.UTF_8);
            assertEquals(expected, test);
        }

        // bad input for coverage
        byte[] decoded = base32Decode("/".toCharArray());
        assertEquals(0, decoded.length);
        decoded = base32Decode(Character.toChars(512));
        assertEquals(0, decoded.length);
    }

    @Test
    public void testEncodeDecodeSeed() throws Exception {
        byte[] bytes = new byte[64];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        char[] encoded = NKeyInternalUtils.encodeSeed(NKeyType.ACCOUNT, bytes);
        NKeyDecodedSeed decoded = NKeyInternalUtils.decodeSeed(encoded);

        assertEquals(NKeyType.ACCOUNT, NKeyType.fromPrefix(decoded.prefix));
        assertArrayEquals(bytes, decoded.bytes);
    }

    @Test
    public void testEncodeDecode() throws Exception {
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        char[] encoded = encode(NKeyType.ACCOUNT, bytes);
        byte[] decoded = decode(NKeyType.ACCOUNT, encoded);
        assertNotNull(decoded);
        assertArrayEquals(bytes, decoded);

        encoded = encode(NKeyType.USER, bytes);
        decoded = decode(NKeyType.USER, encoded);
        assertNotNull(decoded);
        assertArrayEquals(bytes, decoded);

        encoded = encode(NKeyType.SERVER, bytes);
        decoded = decode(NKeyType.SERVER, encoded);
        assertNotNull(decoded);
        assertArrayEquals(bytes, decoded);

        encoded = encode(NKeyType.CLUSTER, bytes);
        decoded = decode(NKeyType.CLUSTER, encoded);
        assertNotNull(decoded);
        assertArrayEquals(bytes, decoded);
    }

    @Test
    public void testDecodeWrongType() {
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        char[] encoded = new char[0];
        try {
            encoded = encode(NKeyType.ACCOUNT, bytes);
        }
        catch (IOException e) {
            fail();
        }
        char[] fEncoded = encoded;
        assertThrows(IllegalArgumentException.class, () -> decode(NKeyType.USER, fEncoded));
    }

    @Test
    public void testEncodeSeedSize() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] bytes = new byte[48];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);

            NKeyInternalUtils.encodeSeed(NKeyType.ACCOUNT, bytes);
        });
    }

    @Test
    public void testDecodeSize() {
        assertThrows(IllegalArgumentException.class, () -> decode(NKeyType.ACCOUNT, "".toCharArray()));
    }

    @Test
    public void testBadCRC() throws Exception {
        for (int i = 0; i < 10000; i++) {
            byte[] bytes = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);

            char[] encoded = encode(NKeyType.ACCOUNT, bytes);

            StringBuilder builder = new StringBuilder();
            for (int j = 0; j < encoded.length; j++) {
                if (j == 6) {
                    char c = encoded[j];
                    if (c == 'x' || c == 'X') {
                        builder.append('Z');
                    } else {
                        builder.append('X');
                    }
                } else {
                    builder.append(encoded[j]);
                }
            }

            assertThrows(IllegalArgumentException.class, () -> decode(NKeyType.ACCOUNT, builder.toString().toCharArray()));
        }
    }

    /*
        Compatibility/Interop data created from the following go code:
    	user, _ := nkeys.CreateUser(nil)
        seed, _ := user.Seed()
        publicKey, _ := user.PublicKey()
        privateKey, _ := user.PrivateKey()

        data := []byte("Hello World")
        sig, _ := user.Sign(data)
        encSig := base64.URLEncoding.EncodeToString(sig)

        fmt.Printf("Seed: %q\n", seed)
        fmt.Printf("Public: %q\n", publicKey)
        fmt.Printf("Private: %q\n", privateKey)

        fmt.Printf("Data: %q\n", data)
        fmt.Printf("Signature: %q\n", encSig)
     */
    @Test
    public void testInterop() throws Exception {
        char[] seed = "SUAOXETHU4AZD2424VFDTDJ4TOEUSGZIXMRS6F3MSCMHUUORYHNEVM6ADE".toCharArray();
        char[] publicKey = "UB2YRJYJEFC5GZA5I47TCYYBIXQRAUA6B3MC4SR2WTXNUX6MTYM6BTBP".toCharArray();
        char[] privateKey = "PDVZEZ5HAGI6XGXFJI4Y2PE3RFERWKF3EMXRO3EQTB5FDUOB3JFLG5MIU4ESCROTMQOUOPZRMMAULYIQKAPA5WBOJI5LJ3W2L7GJ4GPAINHQ".toCharArray();
        String encodedSig = "dMSvD2P1Fm6knQGdMwz5h41aPYIOiPqwR-a3b7UNVJr4FcEfFoAIRbm_gtvLGIpplHTc7sZnSMeaS3Ogm1W_CA";
        String nonce = "UkY0TGZNbEVianJZY09F";
        String nonceEncodedSig = "ZNNvu8FDPhpVlyIqjfZGnLCmoAUQggdfdvhGtWLy29AM9TSa6_j15J2iph37j6_FvkGdd1v3crDANwHCqJuQCw";
        byte[] data = "Hello World".getBytes(StandardCharsets.UTF_8);
        NKey fromSeed = getProvider().fromSeed(seed);
        NKey fromPublicKey = getProvider().fromPublicKey(publicKey);

        assertEquals(NKeyType.USER, fromSeed.getType());

        byte[] nonceData = Base64.getUrlDecoder().decode(nonce);
        byte[] nonceSig = Base64.getUrlDecoder().decode(nonceEncodedSig);
        byte[] seedNonceSig = fromSeed.sign(nonceData);
        String encodedSeedNonceSig = Base64.getUrlEncoder().withoutPadding().encodeToString(seedNonceSig);

        assertArrayEquals(seedNonceSig, nonceSig);
        assertEquals(nonceEncodedSig, encodedSeedNonceSig);

        assertTrue(fromSeed.verify(nonceData, nonceSig));
        assertTrue(fromPublicKey.verify(nonceData, nonceSig));
        assertTrue(fromSeed.verify(nonceData, seedNonceSig));
        assertTrue(fromPublicKey.verify(nonceData, seedNonceSig));

        byte[] seedSig = fromSeed.sign(data);
        byte[] sig = Base64.getUrlDecoder().decode(encodedSig);
        String encodedSeedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(seedSig);

        assertArrayEquals(seedSig, sig);
        assertEquals(encodedSig, encodedSeedSig);

        assertTrue(fromSeed.verify(data, sig));
        assertTrue(fromPublicKey.verify(data, sig));
        assertTrue(fromSeed.verify(data, seedSig));
        assertTrue(fromPublicKey.verify(data, seedSig));

        // Make sure generation is the same
        assertArrayEquals(fromSeed.getSeed(), seed);
        assertArrayEquals(fromSeed.getPublicKey(), publicKey);
        assertArrayEquals(fromSeed.getPrivateKey(), privateKey);

        NKeyDecodedSeed decoded = NKeyInternalUtils.decodeSeed(seed);
        char[] encodedSeed = NKeyInternalUtils.encodeSeed(NKeyType.fromPrefix(decoded.prefix), decoded.bytes);
        assertArrayEquals(encodedSeed, seed);
    }

    @Test
    public void testTypeEnum() {
        assertEquals(NKeyType.USER, NKeyType.fromPrefix(PREFIX_BYTE_USER));
        assertEquals(NKeyType.ACCOUNT, NKeyType.fromPrefix(PREFIX_BYTE_ACCOUNT));
        assertEquals(NKeyType.SERVER, NKeyType.fromPrefix(PREFIX_BYTE_SERVER));
        assertEquals(NKeyType.OPERATOR, NKeyType.fromPrefix(PREFIX_BYTE_OPERATOR));
        assertEquals(NKeyType.CLUSTER, NKeyType.fromPrefix(PREFIX_BYTE_CLUSTER));
        assertEquals(NKeyType.ACCOUNT, NKeyType.fromPrefix(PREFIX_BYTE_PRIVATE));
        assertNull(NKeyType.fromPrefix(9999));
    }

    @Test
    public void testRemovePaddingAndClear() {
        char[] withPad = "!".toCharArray();
        char[] removed = removePaddingAndClear(withPad);
        assertEquals(withPad.length, removed.length);
        assertEquals('!', removed[0]);

        withPad = "a=".toCharArray();
        removed = removePaddingAndClear(withPad);
        assertEquals(1, removed.length);
        assertEquals('a', removed[0]);
    }
}
