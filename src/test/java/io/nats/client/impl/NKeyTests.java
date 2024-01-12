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

package io.nats.client.impl;

import io.ResourceUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class NKeyTests {
    private static final int ED25519_SIGNATURE_SIZE = 64;

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
            int actual = Common.crc16(input);
            assertEquals(crc, actual, String.format("CRC for \"%s\", should be 0x%08X but was 0x%08X", Arrays.toString(input), crc, actual));
        }
    }

    @Test
    public void testBase32() {
        List<String> inputs = ResourceUtils.resourceAsLines("utf8-test-strings.txt");

        for (String expected : inputs) {
            byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
            char[] encoded = Common.base32Encode(bytes);
            byte[] decoded = Common.base32Decode(encoded);
            String test = new String(decoded, StandardCharsets.UTF_8);
            assertEquals(test, expected);
        }

        // bad input for coverage
        byte[] decoded = Common.base32Decode("/".toCharArray());
        assertEquals(0, decoded.length);
        decoded = Common.base32Decode(Character.toChars(512));
        assertEquals(0, decoded.length);
    }

    @Test
    public void testEncodeDecodeSeed() throws Exception {
        byte[] bytes = new byte[64];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        char[] encoded = NKey.encodeSeed(NKeyType.ACCOUNT, bytes);
        DecodedSeed decoded = NKey.decodeSeed(encoded);

        assertEquals(NKeyType.fromPrefix(decoded.prefix), NKeyType.ACCOUNT);
        assertArrayEquals(bytes, decoded.bytes);
    }

    @Test
    public void testEncodeDecode() throws Exception {
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        char[] encoded = NKey.encode(NKeyType.ACCOUNT, bytes);
        byte[] decoded = NKey.decode(NKeyType.ACCOUNT, encoded, false);
        assertArrayEquals(bytes, decoded);

        encoded = NKey.encode(NKeyType.USER, bytes);
        decoded = NKey.decode(NKeyType.USER, encoded, false);
        assertArrayEquals(bytes, decoded);

        encoded = NKey.encode(NKeyType.SERVER, bytes);
        decoded = NKey.decode(NKeyType.SERVER, encoded, false);
        assertArrayEquals(bytes, decoded);

        encoded = NKey.encode(NKeyType.CLUSTER, bytes);
        decoded = NKey.decode(NKeyType.CLUSTER, encoded, false);
        assertArrayEquals(bytes, decoded);
    }

    @Test
    public void testDecodeWrongType() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] bytes = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);

            char[] encoded = NKey.encode(NKeyType.ACCOUNT, bytes);
            NKey.decode(NKeyType.USER, encoded, false);
        });
    }

    @Test
    public void testEncodeSeedSize() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] bytes = new byte[48];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);

            NKey.encodeSeed(NKeyType.ACCOUNT, bytes);
        });
    }

    @Test
    public void testDecodeSize() {
        assertThrows(IllegalArgumentException.class, () -> NKey.decode(NKeyType.ACCOUNT, "".toCharArray(), false));
    }

    @Test
    public void testBadCRC() throws Exception {
        for (int i = 0; i < 10000; i++) {
            try {
                byte[] bytes = new byte[32];
                SecureRandom random = new SecureRandom();
                random.nextBytes(bytes);

                char[] encoded = NKey.encode(NKeyType.ACCOUNT, bytes);

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

                NKey.decode(NKeyType.ACCOUNT, builder.toString().toCharArray(), false);
                fail();
            } catch (IllegalArgumentException e) {
                //expected
            }
        }
    }

    @Test
    public void testAccount() throws Exception {
        NKey theKey = NKey.createAccount(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKey.decodeSeed(seed); // throws if there is an issue

        assertEquals(NKey.fromSeed(theKey.getSeed()), NKey.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals(publicKey[0], 'A');

        char[] privateKey = theKey.getPrivateKey();
        assertEquals(privateKey[0], 'P');

        byte[] data = "Synadia".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = NKey.createAccount(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(NKey.isValidPublicAccountKey(publicKey));
        assertFalse(NKey.isValidPublicClusterKey(publicKey));
        assertFalse(NKey.isValidPublicOperatorKey(publicKey));
        assertFalse(NKey.isValidPublicUserKey(publicKey));
        assertFalse(NKey.isValidPublicServerKey(publicKey));
    }

    @Test
    public void testUser() throws Exception {
        NKey theKey = NKey.createUser(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKey.decodeSeed(seed); // throws if there is an issue

        assertEquals(NKey.fromSeed(theKey.getSeed()), NKey.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals(publicKey[0], 'U');

        char[] privateKey = theKey.getPrivateKey();
        assertEquals(privateKey[0], 'P');

        byte[] data = "Mister Zero".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = NKey.createUser(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(NKey.isValidPublicUserKey(publicKey));
        assertFalse(NKey.isValidPublicAccountKey(publicKey));
        assertFalse(NKey.isValidPublicClusterKey(publicKey));
        assertFalse(NKey.isValidPublicOperatorKey(publicKey));
        assertFalse(NKey.isValidPublicServerKey(publicKey));
    }

    @Test
    public void testCluster() throws Exception {
        NKey theKey = NKey.createCluster(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKey.decodeSeed(seed); // throws if there is an issue

        assertEquals(NKey.fromSeed(theKey.getSeed()), NKey.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals(publicKey[0], 'C');

        char[] privateKey = theKey.getPrivateKey();
        assertEquals(privateKey[0], 'P');

        byte[] data = "Connect Everything".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = NKey.createCluster(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(NKey.isValidPublicClusterKey(publicKey));
        assertFalse(NKey.isValidPublicAccountKey(publicKey));
        assertFalse(NKey.isValidPublicOperatorKey(publicKey));
        assertFalse(NKey.isValidPublicUserKey(publicKey));
        assertFalse(NKey.isValidPublicServerKey(publicKey));
    }

    @Test
    public void testOperator() throws Exception {
        NKey theKey = NKey.createOperator(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKey.decodeSeed(seed); // throws if there is an issue

        assertEquals(NKey.fromSeed(theKey.getSeed()), NKey.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals(publicKey[0], 'O');

        char[] privateKey = theKey.getPrivateKey();
        assertEquals(privateKey[0], 'P');

        byte[] data = "Connect Everything".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = NKey.createOperator(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(NKey.isValidPublicOperatorKey(publicKey));
        assertFalse(NKey.isValidPublicAccountKey(publicKey));
        assertFalse(NKey.isValidPublicClusterKey(publicKey));
        assertFalse(NKey.isValidPublicUserKey(publicKey));
        assertFalse(NKey.isValidPublicServerKey(publicKey));
    }

    @Test
    public void testServer() throws Exception {
        NKey theKey = NKey.createServer(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKey.decodeSeed(seed); // throws if there is an issue

        assertEquals(NKey.fromSeed(theKey.getSeed()), NKey.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals(publicKey[0], 'N');

        char[] privateKey = theKey.getPrivateKey();
        assertEquals(privateKey[0], 'P');

        byte[] data = "Polaris and Pluto".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = NKey.createServer(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(NKey.isValidPublicServerKey(publicKey));
        assertFalse(NKey.isValidPublicAccountKey(publicKey));
        assertFalse(NKey.isValidPublicClusterKey(publicKey));
        assertFalse(NKey.isValidPublicOperatorKey(publicKey));
        assertFalse(NKey.isValidPublicUserKey(publicKey));
    }

    @Test
    public void testPublicOnly() throws Exception {
        NKey theKey = NKey.createUser(null);
        assertNotNull(theKey);

        char[] publicKey = theKey.getPublicKey();

        assertEquals(NKey.fromPublicKey(publicKey), NKey.fromPublicKey(publicKey));
        assertEquals(NKey.fromPublicKey(publicKey).hashCode(), NKey.fromPublicKey(publicKey).hashCode());

        NKey pubOnly = NKey.fromPublicKey(publicKey);

        //noinspection EqualsWithItself
        assertEquals(pubOnly, pubOnly); // for coverage

        byte[] data = "Public and Private".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertTrue(pubOnly.verify(data, sig));

        NKey otherKey = NKey.createServer(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);
        assertNotEquals(otherKey, pubOnly);

        assertNotEquals(pubOnly.getPublicKey()[0], '\0');
        pubOnly.clear();
        assertEquals(pubOnly.getPublicKey()[0], '\0');
    }

    @Test
    public void testPublicOnlyCantSign() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = NKey.createUser(null);
            NKey pubOnly = NKey.fromPublicKey(theKey.getPublicKey());

            byte[] data = "Public and Private".getBytes(StandardCharsets.UTF_8);
            pubOnly.sign(data);
        });
    }

    @Test
    public void testPublicOnlyCantProvideSeed() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = NKey.createUser(null);
            NKey pubOnly = NKey.fromPublicKey(theKey.getPublicKey());
            pubOnly.getSeed();
        });
    }

    @Test
    public void testPublicOnlyCantProvidePrivate() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = NKey.createUser(null);
            NKey pubOnly = NKey.fromPublicKey(theKey.getPublicKey());
            pubOnly.getPrivateKey();
        });
    }

    @Test
    public void testPublicFromSeedShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey theKey = NKey.createUser(null);
            NKey.fromPublicKey(theKey.getSeed());
        });
    }

    @Test
    public void testSeedFromPublicShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey theKey = NKey.createUser(null);
            NKey.fromSeed(theKey.getPublicKey());
        });
    }

    @Test
    public void testFromSeed() throws Exception {
        NKey theKey = NKey.createAccount(null);
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        assertEquals(NKey.fromSeed(seed), NKey.fromSeed(seed));
        assertEquals(NKey.fromSeed(seed).hashCode(), NKey.fromSeed(seed).hashCode());
        assertArrayEquals(NKey.fromSeed(seed).getPublicKey(), NKey.fromSeed(seed).getPublicKey());
        assertArrayEquals(NKey.fromSeed(seed).getPrivateKey(), NKey.fromSeed(seed).getPrivateKey());

        assertTrue(seed[0] == 'S' && seed[1] == 'A');

        NKey fromSeed = NKey.fromSeed(seed);

        byte[] data = "Seeds into trees".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertTrue(fromSeed.verify(data, sig));

        NKey otherKey = NKey.createServer(null);
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);
        assertNotEquals(otherKey, fromSeed);
    }

    @Test
    public void testFromBadSeed() {
        assertThrows(IllegalArgumentException.class, () -> NKey.fromSeed("BadSeed".toCharArray()));
    }

    @Test
    public void testFromBadPublicKey() {
        assertThrows(IllegalArgumentException.class, () -> NKey.fromPublicKey("BadSeed".toCharArray()));
    }

    @Test
    public void testBigSignVerify() throws Exception {
        NKey theKey = NKey.createAccount(null);
        assertNotNull(theKey);

        byte[] data = ResourceUtils.resourceAsBytes("keystore.jks");
        byte[] sig = theKey.sign(data);

        assertEquals(sig.length, ED25519_SIGNATURE_SIZE);
        assertTrue(theKey.verify(data, sig));

        char[] publicKey = theKey.getPublicKey();
        assertTrue(NKey.fromPublicKey(publicKey).verify(data, sig));

        NKey otherKey = NKey.createUser(null);
        byte[] sig2 = otherKey.sign(data);

        assertFalse(otherKey.verify(data, sig));
        assertFalse(Arrays.equals(sig2, sig));
        assertTrue(otherKey.verify(data, sig2));
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
        NKey fromSeed = NKey.fromSeed(seed);
        NKey fromPublicKey = NKey.fromPublicKey(publicKey);

        assertEquals(fromSeed.getType(), NKeyType.USER);

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

        DecodedSeed decoded = NKey.decodeSeed(seed);
        char[] encodedSeed = NKey.encodeSeed(NKeyType.fromPrefix(decoded.prefix), decoded.bytes);
        assertArrayEquals(encodedSeed, seed);
    }

    @Test
    public void testTypeEnum() {
        assertEquals(NKeyType.USER, NKeyType.fromPrefix(Common.PREFIX_BYTE_USER));
        assertEquals(NKeyType.ACCOUNT, NKeyType.fromPrefix(Common.PREFIX_BYTE_ACCOUNT));
        assertEquals(NKeyType.SERVER, NKeyType.fromPrefix(Common.PREFIX_BYTE_SERVER));
        assertEquals(NKeyType.OPERATOR, NKeyType.fromPrefix(Common.PREFIX_BYTE_OPERATOR));
        assertEquals(NKeyType.CLUSTER, NKeyType.fromPrefix(Common.PREFIX_BYTE_CLUSTER));
        assertEquals(NKeyType.ACCOUNT, NKeyType.fromPrefix(Common.PREFIX_BYTE_PRIVATE));
        assertThrows(IllegalArgumentException.class, () -> { NKeyType ignored = NKeyType.fromPrefix(9999); });
    }

    @Test
    public void testRemovePaddingAndClear() {
        char[] withPad = "!".toCharArray();
        char[] removed = NKey.removePaddingAndClear(withPad);
        assertEquals(withPad.length, removed.length);
        assertEquals('!', removed[0]);

        withPad = "a=".toCharArray();
        removed = NKey.removePaddingAndClear(withPad);
        assertEquals(1, removed.length);
        assertEquals('a', removed[0]);
    }

    @Test
    public void testEquals() throws Exception {
        NKey key = NKey.createServer(null);
        //noinspection EqualsWithItself
        assertEquals(key, key);
        assertEquals(key, NKey.fromSeed(key.getSeed()));
        assertNotEquals(key, new Object());
        assertNotEquals(key, NKey.createServer(null));
        assertNotEquals(key, NKey.createAccount(null));
    }

    @Test
    public void testClear() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey key = NKey.createServer(null);
            key.clear();
            key.getPrivateKey();

        }, "Invalid encoding");
    }
}
