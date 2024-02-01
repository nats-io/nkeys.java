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

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.util.Arrays;

import static io.nats.nkey.NKeyConstants.*;
import static io.nats.nkey.NKeyUtils.*;

public class NKey {

    private static boolean notValidPublicPrefixByte(int prefix) {
        switch (prefix) {
            case PREFIX_BYTE_SERVER:
            case PREFIX_BYTE_CLUSTER:
            case PREFIX_BYTE_OPERATOR:
            case PREFIX_BYTE_ACCOUNT:
            case PREFIX_BYTE_USER:
                return false;
        }
        return true;
    }

    static char[] removePaddingAndClear(char[] withPad) {
        int i;

        for (i=withPad.length-1;i>=0;i--) {
            if (withPad[i] != '=') {
                break;
            }
        }
        char[] withoutPad = new char[i+1];
        System.arraycopy(withPad, 0, withoutPad, 0, withoutPad.length);

        Arrays.fill(withPad, '\0');

        return withoutPad;
    }

    static char[] encode(NkeyType type, byte[] src) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        bytes.write(type.prefix);
        bytes.write(src);

        int crc = crc16(bytes.toByteArray());
        byte[] littleEndian = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) crc).array();

        bytes.write(littleEndian);

        char[] withPad = base32Encode(bytes.toByteArray());
        return removePaddingAndClear(withPad);
    }

    static char[] encodeSeed(NkeyType type, byte[] src) throws IOException {
        if (src.length != ED25519_PRIVATE_KEYSIZE && src.length != ED25519_SEED_SIZE) {
            throw new IllegalArgumentException("Source is not the correct size for an ED25519 seed");
        }

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

    static byte[] decode(char[] src) {
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

    static byte[] decode(NkeyType expectedType, char[] src) {
        byte[] raw = decode(src);
        byte[] dataBytes = Arrays.copyOfRange(raw, 1, raw.length);
        NkeyType type = NkeyType.fromPrefix(raw[0] & 0xFF);

        if (type != expectedType) {
            return null;
        }

        return dataBytes;
    }

    static NKeyDecodedSeed decodeSeed(char[] seed) {
        byte[] raw = decode(seed);

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

    private static NKey createPair(NkeyType type, SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        if (random == null) {
            random = SRAND;
        }

        byte[] seed = new byte[ED_25519.getCurve().getField().getb() / 8];
        random.nextBytes(seed);

        return createPair(type, seed);
    }

    private static NKey createPair(NkeyType type, byte[] seed)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seed, ED_25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), ED_25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);
        byte[] pubBytes = pubKey.getAbyte();

        byte[] bytes = new byte[pubBytes.length + seed.length];
        System.arraycopy(seed, 0, bytes, 0, seed.length);
        System.arraycopy(pubBytes, 0, bytes, seed.length, pubBytes.length);

        char[] encoded = encodeSeed(type, bytes);
        return new NKey(type, null, encoded);
    }

    /**
     * Create an Account NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @param random A secure random provider
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     * @throws NoSuchProviderException if the default secure random cannot be created
     * @throws NoSuchAlgorithmException if the default secure random cannot be created
     */
    public static NKey createAccount(SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        return createPair(NkeyType.ACCOUNT, random);
    }

    /**
     * Create a Cluster NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @param random A secure random provider
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     * @throws NoSuchProviderException if the default secure random cannot be created
     * @throws NoSuchAlgorithmException if the default secure random cannot be created
     */
    public static NKey createCluster(SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        return createPair(NkeyType.CLUSTER, random);
    }

    /**
     * Create an Operator NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @param random A secure random provider
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     * @throws NoSuchProviderException if the default secure random cannot be created
     * @throws NoSuchAlgorithmException if the default secure random cannot be created
     */
    public static NKey createOperator(SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        return createPair(NkeyType.OPERATOR, random);
    }

    /**
     * Create a Server NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @param random A secure random provider
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     * @throws NoSuchProviderException if the default secure random cannot be created
     * @throws NoSuchAlgorithmException if the default secure random cannot be created
     */
    public static NKey createServer(SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        return createPair(NkeyType.SERVER, random);
    }

    /**
     * Create a User NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @param random A secure random provider
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     * @throws NoSuchProviderException if the default secure random cannot be created
     * @throws NoSuchAlgorithmException if the default secure random cannot be created
     */
    public static NKey createUser(SecureRandom random)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        return createPair(NkeyType.USER, random);
    }

    /**
     * Create an NKey object from the encoded public key. This NKey can be used for verification but not for signing.
     * @param publicKey the string encoded public key
     * @return the new NKey
     */
    public static NKey fromPublicKey(char[] publicKey) {
        byte[] raw = decode(publicKey);
        int prefix = raw[0] & 0xFF;

        if (notValidPublicPrefixByte(prefix)) {
            throw new IllegalArgumentException("Not a valid public NKey");
        }

        NkeyType type = NkeyType.fromPrefix(prefix);
        return new NKey(type, publicKey, null);
    }

    /**
     * Creates an NKey object from a string encoded seed. This NKey can be used to sign or verify.
     * @param seed the string encoded seed, see {@link NKey#getSeed() getSeed()}
     * @return the NKey
     */
    public static NKey fromSeed(char[] seed) {
        NKeyDecodedSeed decoded = decodeSeed(seed); // Should throw on bad seed

        if (decoded.bytes.length == ED25519_PRIVATE_KEYSIZE) {
            return new NKey(NkeyType.fromPrefix(decoded.prefix), null, seed);
        } else {
            try {
                return createPair(NkeyType.fromPrefix(decoded.prefix), decoded.bytes);
            } catch (Exception e) {
                throw new IllegalArgumentException("Bad seed value", e);
            }
        }
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is an account public key
     */
    public static boolean isValidPublicAccountKey(char[] src) {
        return decode(NkeyType.ACCOUNT, src) != null;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a cluster public key
     */
    public static boolean isValidPublicClusterKey(char[] src) {
        return decode(NkeyType.CLUSTER, src) != null;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is an operator public key
     */
    public static boolean isValidPublicOperatorKey(char[] src) {
        return decode(NkeyType.OPERATOR, src) != null;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a server public key
     */
    public static boolean isValidPublicServerKey(char[] src) {
        return decode(NkeyType.SERVER, src) != null;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a user public key
     */
    public static boolean isValidPublicUserKey(char[] src) {
        return decode(NkeyType.USER, src) != null;
    }

    /**
     * The seed or private key per the Ed25519 spec, encoded with encodeSeed.
     */
    private final char[] privateKeyAsSeed;

    /**
     * The public key, maybe null. Used for public only NKeys.
     */
    private final char[] publicKey;

    private final NkeyType type;

    private NKey(NkeyType t, char[] publicKey, char[] privateKey) {
        this.type = t;
        this.privateKeyAsSeed = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Clear the seed and public key char arrays by filling them
     * with random bytes then zero-ing them out.
     * The nkey is unusable after this operation.
     */
    public void clear() {
        if (privateKeyAsSeed != null) {
            for (int i=0; i< privateKeyAsSeed.length ; i++) {
                privateKeyAsSeed[i] = (char)(PRAND.nextInt(26) + 'a');
            }
            Arrays.fill(privateKeyAsSeed, '\0');
        }
        if (publicKey != null) {
            for (int i=0; i< publicKey.length ; i++) {
                publicKey[i] = (char)(PRAND.nextInt(26) + 'a');
            }
            Arrays.fill(publicKey, '\0');
        }
    }

    /**
     * @return the string encoded seed for this NKey
     */
    public char[] getSeed() {
        if (privateKeyAsSeed == null) {
            throw new IllegalStateException("Public-only NKey");
        }
        NKeyDecodedSeed decoded = decodeSeed(privateKeyAsSeed);
        byte[] seedBytes = new byte[ED25519_SEED_SIZE];
        System.arraycopy(decoded.bytes, 0, seedBytes, 0, seedBytes.length);
        try {
            return encodeSeed(NkeyType.fromPrefix(decoded.prefix), seedBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create seed.", e);
        }
    }

    /**
     * @return the encoded public key for this NKey
     *
     * @throws GeneralSecurityException if there is an encryption problem
     * @throws IOException              if there is a problem encoding the public
     *                                  key
     */
    public char[] getPublicKey() throws GeneralSecurityException, IOException {
        if (publicKey != null) {
            return publicKey;
        }

        KeyPair keys = getKeyPair();
        EdDSAPublicKey pubKey = (EdDSAPublicKey) keys.getPublic();
        byte[] pubBytes = pubKey.getAbyte();

        return encode(this.type, pubBytes);
    }

    /**
     * @return the encoded private key for this NKey
     *
     * @throws GeneralSecurityException if there is an encryption problem
     * @throws IOException              if there is a problem encoding the key
     */
    public char[] getPrivateKey() throws GeneralSecurityException, IOException {
        if (privateKeyAsSeed == null) {
            throw new IllegalStateException("Public-only NKey");
        }

        NKeyDecodedSeed decoded = decodeSeed(privateKeyAsSeed);
        return encode(NkeyType.PRIVATE, decoded.bytes);
    }

    /**
     * @return A Java security keypair that represents this NKey in Java security
     *         form.
     *
     * @throws GeneralSecurityException if there is an encryption problem
     * @throws IOException              if there is a problem encoding or decoding
     */
    public KeyPair getKeyPair() throws GeneralSecurityException, IOException {
        if (privateKeyAsSeed == null) {
            throw new IllegalStateException("Public-only NKey");
        }

        NKeyDecodedSeed decoded = decodeSeed(privateKeyAsSeed);
        byte[] seedBytes = new byte[ED25519_SEED_SIZE];
        byte[] pubBytes = new byte[ED25519_PUBLIC_KEYSIZE];

        System.arraycopy(decoded.bytes, 0, seedBytes, 0, seedBytes.length);
        System.arraycopy(decoded.bytes, seedBytes.length, pubBytes, 0, pubBytes.length);

        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seedBytes, ED_25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(pubBytes, ED_25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);

        return new KeyPair(pubKey, privKey);
    }

    /**
     * @return the Type of this NKey
     */
    public NkeyType getType() {
        return type;
    }

    /**
     * Sign aribitrary binary input.
     *
     * @param input the bytes to sign
     * @return the signature for the input from the NKey
     *
     * @throws GeneralSecurityException if there is an encryption problem
     * @throws IOException              if there is a problem reading the data
     */
    public byte[] sign(byte[] input) throws GeneralSecurityException, IOException {
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(ED_25519.getHashAlgorithm()));
        PrivateKey sKey = getKeyPair().getPrivate();

        sgr.initSign(sKey);
        sgr.update(input);

        return sgr.sign();
    }

    /**
     * Verify a signature.
     *
     * @param input     the bytes that were signed
     * @param signature the bytes for the signature
     * @return true if the signature matches this keys signature for the input.
     *
     * @throws GeneralSecurityException if there is an encryption problem
     * @throws IOException              if there is a problem reading the data
     */
    public boolean verify(byte[] input, byte[] signature) throws GeneralSecurityException, IOException {
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(ED_25519.getHashAlgorithm()));
        PublicKey sKey;

        if (privateKeyAsSeed != null) {
            sKey = getKeyPair().getPublic();
        }
        else {
            char[] encodedPublicKey = getPublicKey();
            byte[] decodedPublicKey = decode(this.type, encodedPublicKey);
            if (decodedPublicKey == null) {
                throw new IllegalArgumentException("Unexpected type");
            }
            EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(decodedPublicKey, ED_25519);
            sKey = new EdDSAPublicKey(pubKeySpec);
        }

        sgr.initVerify(sKey);
        sgr.update(input);

        return sgr.verify(signature);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof NKey)) {
            return false;
        }

        NKey otherNkey = (NKey) o;

        if (this.type != otherNkey.type) {
            return false;
        }

        if (this.privateKeyAsSeed == null) {
            return Arrays.equals(this.publicKey, otherNkey.publicKey);
        }

        return Arrays.equals(this.privateKeyAsSeed, otherNkey.privateKeyAsSeed);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + this.type.prefix;

        if (this.privateKeyAsSeed == null) {
            result = 31 * result + Arrays.hashCode(this.publicKey);
        } else {
            result = 31 * result + Arrays.hashCode(this.privateKeyAsSeed);
        }
        return result;
    }
}
