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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static io.nats.nkey.NKeyUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD;

@Execution(SAME_THREAD)
public class LtsProviderTests {
    private static final int ED25519_SIGNATURE_SIZE = 64;

    private static NKeyProvider PROVIDER;

    @BeforeAll
    static void beforeAll() {
        PROVIDER = new LtsNKeyProvider();
    }

    @Test
    public void testSecureRandom() {
        System.out.println(PROVIDER.getSecureRandom().getClass() + " " + PROVIDER.getSecureRandom());
    }

    @Test
    public void testAccount() {
        NKey theKey = PROVIDER.createAccount();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKeyInternalUtils.decodeSeed(seed); // throws if there is an issue

        assertEquals(PROVIDER.fromSeed(theKey.getSeed()), PROVIDER.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals('A', publicKey[0]);

        char[] privateKey = theKey.getPrivateKey();
        assertEquals('P', privateKey[0]);

        byte[] data = "Synadia".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = PROVIDER.createAccount();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(isValidPublicAccountKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicClusterKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicOperatorKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicUserKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicServerKey(publicKey));
    }

    @Test
    public void testUser() {
        NKey theKey = PROVIDER.createUser();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKeyInternalUtils.decodeSeed(seed); // throws if there is an issue

        assertEquals(PROVIDER.fromSeed(theKey.getSeed()), PROVIDER.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals('U', publicKey[0]);

        char[] privateKey = theKey.getPrivateKey();
        assertEquals('P', privateKey[0]);

        byte[] data = "Mister Zero".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = PROVIDER.createUser();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(isValidPublicUserKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicAccountKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicClusterKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicOperatorKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicServerKey(publicKey));
    }

    @Test
    public void testCluster() {
        NKey theKey = PROVIDER.createCluster();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKeyInternalUtils.decodeSeed(seed); // throws if there is an issue

        assertEquals(PROVIDER.fromSeed(theKey.getSeed()), PROVIDER.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals('C', publicKey[0]);

        char[] privateKey = theKey.getPrivateKey();
        assertEquals('P', privateKey[0]);

        byte[] data = "Connect Everything".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = PROVIDER.createCluster();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(isValidPublicClusterKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicAccountKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicOperatorKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicUserKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicServerKey(publicKey));
    }

    @Test
    public void testOperator() {
        NKey theKey = PROVIDER.createOperator();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKeyInternalUtils.decodeSeed(seed); // throws if there is an issue

        assertEquals(PROVIDER.fromSeed(theKey.getSeed()), PROVIDER.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals('O', publicKey[0]);

        char[] privateKey = theKey.getPrivateKey();
        assertEquals('P', privateKey[0]);

        byte[] data = "Connect Everything".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = PROVIDER.createOperator();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(isValidPublicOperatorKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicAccountKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicClusterKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicUserKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicServerKey(publicKey));
    }

    @Test
    public void testServer() {
        NKey theKey = PROVIDER.createServer();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        NKeyInternalUtils.decodeSeed(seed); // throws if there is an issue

        assertEquals(PROVIDER.fromSeed(theKey.getSeed()), PROVIDER.fromSeed(theKey.getSeed()));

        char[] publicKey = theKey.getPublicKey();
        assertEquals('N', publicKey[0]);

        char[] privateKey = theKey.getPrivateKey();
        assertEquals('P', privateKey[0]);

        byte[] data = "Polaris and Pluto".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);

        assertTrue(theKey.verify(data, sig));

        NKey otherKey = PROVIDER.createServer();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);

        assertTrue(isValidPublicServerKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicAccountKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicClusterKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicOperatorKey(publicKey));
        assertThrows(IllegalArgumentException.class, () -> isValidPublicUserKey(publicKey));
    }

    @Test
    public void testPublicOnly() {
        NKey theKey = PROVIDER.createUser();
        assertNotNull(theKey);

        char[] publicKey = theKey.getPublicKey();

        assertEquals(PROVIDER.fromPublicKey(publicKey), PROVIDER.fromPublicKey(publicKey));
        assertEquals(PROVIDER.fromPublicKey(publicKey).hashCode(), PROVIDER.fromPublicKey(publicKey).hashCode());

        NKey pubOnly = PROVIDER.fromPublicKey(publicKey);

        //noinspection EqualsWithItself
        assertEquals(pubOnly, pubOnly); // for coverage

        byte[] data = "Public and Private".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertTrue(pubOnly.verify(data, sig));

        NKey otherKey = PROVIDER.createServer();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);
        assertNotEquals(otherKey, pubOnly);

        assertNotEquals('\0', pubOnly.getPublicKey()[0]);
        pubOnly.clear();
        assertEquals('\0', pubOnly.getPublicKey()[0]);
    }

    @Test
    public void testPublicOnlyCantSign() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = PROVIDER.createUser();
            NKey pubOnly = PROVIDER.fromPublicKey(theKey.getPublicKey());

            byte[] data = "Public and Private".getBytes(StandardCharsets.UTF_8);
            pubOnly.sign(data);
        });
    }

    @Test
    public void testPublicOnlyCantProvideSeed() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = PROVIDER.createUser();
            NKey pubOnly = PROVIDER.fromPublicKey(theKey.getPublicKey());
            pubOnly.getSeed();
        });
    }

    @Test
    public void testPublicOnlyCantProvidePrivate() {
        assertThrows(IllegalStateException.class, () -> {
            NKey theKey = PROVIDER.createUser();
            NKey pubOnly = PROVIDER.fromPublicKey(theKey.getPublicKey());
            pubOnly.getPrivateKey();
        });
    }

    @Test
    public void testPublicFromSeedShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey theKey = PROVIDER.createUser();
            PROVIDER.fromPublicKey(theKey.getSeed());
        });
    }

    @Test
    public void testSeedFromPublicShouldFail() {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey theKey = PROVIDER.createUser();
            PROVIDER.fromSeed(theKey.getPublicKey());
        });
    }

    @Test
    public void testFromSeed() {
        NKey theKey = PROVIDER.createAccount();
        assertNotNull(theKey);

        char[] seed = theKey.getSeed();
        assertEquals(PROVIDER.fromSeed(seed), PROVIDER.fromSeed(seed));
        assertEquals(PROVIDER.fromSeed(seed).hashCode(), PROVIDER.fromSeed(seed).hashCode());
        assertArrayEquals(PROVIDER.fromSeed(seed).getPublicKey(), PROVIDER.fromSeed(seed).getPublicKey());
        assertArrayEquals(PROVIDER.fromSeed(seed).getPrivateKey(), PROVIDER.fromSeed(seed).getPrivateKey());

        assertTrue(seed[0] == 'S' && seed[1] == 'A');

        NKey fromSeed = PROVIDER.fromSeed(seed);

        byte[] data = "Seeds into trees".getBytes(StandardCharsets.UTF_8);
        byte[] sig = theKey.sign(data);

        assertTrue(fromSeed.verify(data, sig));

        NKey otherKey = PROVIDER.createServer();
        assertFalse(otherKey.verify(data, sig));
        assertNotEquals(otherKey, theKey);
        assertNotEquals(otherKey, fromSeed);
    }

    @Test
    public void testFromBadSeed() {
        assertThrows(IllegalArgumentException.class, () -> PROVIDER.fromSeed("BadSeed".toCharArray()));
    }

    @Test
    public void testFromBadPublicKey() {
        assertThrows(IllegalArgumentException.class, () -> PROVIDER.fromPublicKey("BadSeed".toCharArray()));
    }

    @Test
    public void testBigSignVerify() {
        NKey theKey = PROVIDER.createAccount();
        assertNotNull(theKey);

        byte[] data = ResourceUtils.resourceAsBytes("keystore.jks");
        byte[] sig = theKey.sign(data);

        assertEquals(ED25519_SIGNATURE_SIZE, sig.length);
        assertTrue(theKey.verify(data, sig));

        char[] publicKey = theKey.getPublicKey();
        assertTrue(PROVIDER.fromPublicKey(publicKey).verify(data, sig));

        NKey otherKey = PROVIDER.createUser();
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
    public void testInterop() {
        char[] seed = "SUAOXETHU4AZD2424VFDTDJ4TOEUSGZIXMRS6F3MSCMHUUORYHNEVM6ADE".toCharArray();
        char[] publicKey = "UB2YRJYJEFC5GZA5I47TCYYBIXQRAUA6B3MC4SR2WTXNUX6MTYM6BTBP".toCharArray();
        char[] privateKey = "PDVZEZ5HAGI6XGXFJI4Y2PE3RFERWKF3EMXRO3EQTB5FDUOB3JFLG5MIU4ESCROTMQOUOPZRMMAULYIQKAPA5WBOJI5LJ3W2L7GJ4GPAINHQ".toCharArray();
        String encodedSig = "dMSvD2P1Fm6knQGdMwz5h41aPYIOiPqwR-a3b7UNVJr4FcEfFoAIRbm_gtvLGIpplHTc7sZnSMeaS3Ogm1W_CA";
        String nonce = "UkY0TGZNbEVianJZY09F";
        String nonceEncodedSig = "ZNNvu8FDPhpVlyIqjfZGnLCmoAUQggdfdvhGtWLy29AM9TSa6_j15J2iph37j6_FvkGdd1v3crDANwHCqJuQCw";
        byte[] data = "Hello World".getBytes(StandardCharsets.UTF_8);
        NKey fromSeed = PROVIDER.fromSeed(seed);
        NKey fromPublicKey = PROVIDER.fromPublicKey(publicKey);

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
    public void testEquals() {
        NKey key = PROVIDER.createServer();
        //noinspection EqualsWithItself
        assertEquals(key, key);
        assertEquals(key, PROVIDER.fromSeed(key.getSeed()));
        //noinspection MisorderedAssertEqualsArguments
        assertNotEquals(key, new Object());
        assertNotEquals(key, PROVIDER.createServer());
        assertNotEquals(key, PROVIDER.createAccount());
    }

    @Test
    public void testClear() {
        assertThrows(IllegalArgumentException.class, () -> {
            NKey key = PROVIDER.createServer();
            key.clear();
            key.getPrivateKey();

        }, "Invalid encoding");
    }

    @Test
    public void testPublicKeyFromSeed() {
        // using nsc generated seeds for testing
        NKey pk = PROVIDER.fromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM".toCharArray());
        assertEquals("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", new String(pk.getPublicKey()));

        pk = PROVIDER.fromSeed("SAANWFZ3JINNPERWT3ALE45U7GYT2ZDW6GJUIVPDKUF6GKAX6AISZJMAS4".toCharArray());
        assertEquals("AATEJXG7UX4HFJ6ZPRTP22P6OYZER36YYD3GVBOVW7QHLU32P4QFFTZJ", new String(pk.getPublicKey()));

        pk = PROVIDER.fromSeed("SUAGDLNBWI2SGHDRYBHD63NH5FGZSVJUW2J7GAJZXWANQFLDW6G5SXZESU".toCharArray());
        assertEquals("UBICBTHDKQRB4LIYA6BMIJ7EA2G7YS7FIWMMVKZJE6M3HS5IVCOLKDY2", new String(pk.getPublicKey()));
    }

    @Test
    public void testFromPublicKey() {
        _testFromPublicKey("SUAHBVFYZF3DIEO4UIHIZMJICVLURLBM5JJPK7GSVGP2QUC3NZ323BRE6A", "UCM5BG6AAZSEGREBCLG7PG4GFQNJABSAVIXC6VWS7TDHZFPIYFVYHIDG");
        _testFromPublicKey("SAADARCQJ3JA737Z443YNAZBNJNTFP7YNAF4QFUXKTBFBS4KAVK55DGSOQ", "AD2HQTUKOPBUGOPHA6KFRE6ZW5TH43D7P7E56OAQBZQLW2ECMNML6MVA");
        _testFromPublicKey("SNAH645525YA4PNXHWWS46VNXXQTYAXOPKGHXYAHXZZ43XTDDG2ZQAX7LY", "NBZCD2OSMSDRVYCAI77HUN6A2WNDWNT2DMVVEW66DHNWCDXVOUWRCCK7");
        _testFromPublicKey("SOAF5OP7UPK6XJCMNRYEJRET6YQSOE3FD4I4ERSN6WKHLYUC5AQDCOAFVY", "OA6SJACXYP2QGNLU4QYLJTVRVZPCZEEUNO2UQOVNGXYUPUJJHCVZIZQ2");
        _testFromPublicKey("SCAP4LGVURDWVL37AZIM5O47UKANFI6FKBY77HMYF55CKW2XFKLNUBTTFE", "CAO36T42KFA2LMIZ6YHJKPQEJWT5ULYSV633FWBCEJ7MREZPHHC56BSC");
    }

    private static void _testFromPublicKey(String userEncodedSeed, String userEncodedPubKey) {
        NKey fromSeed = PROVIDER.fromSeed(userEncodedSeed.toCharArray());
        NKey fromKey = PROVIDER.fromPublicKey(fromSeed.getPublicKey());

        assertArrayEquals(fromSeed.getPublicKey(), fromKey.getPublicKey());
        assertArrayEquals(userEncodedPubKey.toCharArray(), fromSeed.getPublicKey());
        assertArrayEquals(userEncodedPubKey.toCharArray(), fromKey.getPublicKey());
    }
}
