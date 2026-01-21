// Copyright 2020-2025 The NATS Authors
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

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Random;

import static io.nats.nkey.NKeyConstants.*;
import static io.nats.nkey.NKeyInternalUtils.*;

@NullMarked
public abstract class NKeyProvider {

    private static @Nullable NKeyProvider NKEY_PROVIDER_INSTANCE;

    /**
     * Get the static instance NKeyProvider
     * @return the NKeyProvider instance
     * @throws RuntimeException wrapping any exception
     */
    public static NKeyProvider getProvider() {
        if (NKEY_PROVIDER_INSTANCE == null) {
            try {
                String className = System.getenv(NKEY_PROVIDER_CLASS_ENVIRONMENT_VAR);
                if (className == null) {
                    className = System.getProperty(NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY);
                }
                if (className == null) {
                    throw new IllegalArgumentException("NKeyProvider class environment variable or system property is not set.");
                }
                NKEY_PROVIDER_INSTANCE = getProvider(className);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return NKEY_PROVIDER_INSTANCE;
    }

    /**
     * Get a new NKeyProvider instance
     * @param className the class name used by Class.forName
     * @return an NKeyProvider instance
     * @throws ClassNotFoundException if the class cannot be located
     * @throws NoSuchMethodException if a matching constructor is not found,
     *         including when this {@code Class} object represents
     *         an interface, a primitive type, an array class, or void.
     * @throws InstantiationException if the class that declares the
     *         underlying constructor represents an abstract class.
     * @throws InvocationTargetException if the underlying constructor
     *         throws an exception.
     * @throws ExceptionInInitializerError if the initialization provoked
     *         by this method fails.
     */
    public static NKeyProvider getProvider(String className) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Class<?> clazz = Class.forName(className);
        Constructor<?> constructor = clazz.getConstructor();
        return (NKeyProvider) constructor.newInstance();
    }

    /**
     * Clear the current instance of the provider.
     * Forces the static instance to be reset and re-made when calling getProvider
     */
    public static void clearInstance() {
        NKEY_PROVIDER_INSTANCE = null;
    }

    protected @Nullable SecureRandom secureRandom;
    protected @Nullable Random insecureRandom;

    protected NKeyProvider() {}

    protected NKeyProvider setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    protected NKeyProvider setInsecureRandom(Random insecureRandom) {
        this.insecureRandom = insecureRandom;
        return this;
    }

    public SecureRandom getSecureRandom() {
        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }
        return secureRandom;
    }

    public Random getRandom() {
        if (insecureRandom == null) {
            byte[] bytes = getSecureRandom().generateSeed(8);
            ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE);
            buffer.put(bytes);
            buffer.flip();// need flip
            insecureRandom = new Random(buffer.getLong()); // seed with 8 bytes (64 bits)
        }
        return insecureRandom;
    }

    public NKey createPair(NKeyType type) throws IOException {
        byte[] seed = new byte[ED25519_SEED_SIZE];
        getSecureRandom().nextBytes(seed);
        return createPair(type, seed);
    }

    public abstract NKey createPair(NKeyType type, byte[] seed) throws IOException;

    /**
     * Create an Account NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     */
    public NKey createAccount() throws IOException {
        return createPair(NKeyType.ACCOUNT);
    }

    /**
     * Create a Cluster NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     */
    public NKey createCluster() throws IOException {
        return createPair(NKeyType.CLUSTER);
    }

    /**
     * Create an Operator NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     */
    public NKey createOperator() throws IOException {
        return createPair(NKeyType.OPERATOR);
    }

    /**
     * Create a Server NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     */
    public NKey createServer() throws IOException {
        return createPair(NKeyType.SERVER);
    }

    /**
     * Create a User NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     * @throws IOException if the seed cannot be encoded to a string
     */
    public NKey createUser() throws IOException {
        return createPair(NKeyType.USER);
    }

    /**
     * Create an NKey object from the encoded public key. This NKey can be used for verification but not for signing.
     * @param publicKey the string encoded public key
     * @return the new NKey
     */
    public NKey fromPublicKey(char[] publicKey) {
        byte[] raw = decode(publicKey);
        int prefix = raw[0] & 0xFF;

        if (notValidPublicPrefixByte(prefix)) {
            throw new IllegalArgumentException("Not a valid public NKey");
        }

        NKeyType type = NKeyType.fromPrefix(prefix);
        return new NKey(this, type, publicKey, null);
    }

    /**
     * Creates an NKey object from a string encoded seed. This NKey can be used to sign or verify.
     * @param seed the string encoded seed, see {@link NKey#getSeed() getSeed()}
     * @return the NKey
     */
    public NKey fromSeed(char[] seed) {
        NKeyDecodedSeed decoded = decodeSeed(seed); // Should throw on bad seed

        if (decoded.bytes.length == ED25519_PRIVATE_KEYSIZE) {
            return new NKey(this, NKeyType.fromPrefix(decoded.prefix), null, seed);
        }

        try {
            NKeyType t = NKeyType.fromPrefix(decoded.prefix);
            if (t == null) {
                throw new IllegalArgumentException("Seed contains invalid or unknown prefix");
            }
            return createPair(t, decoded.bytes);
        }
        catch (IllegalArgumentException e) {
            throw e;
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Bad seed value", e);
        }
    }

    public abstract KeyPair getKeyPair(NKey nkey);

    public abstract byte[] sign(NKey nkey, byte[] input);

    public abstract boolean verify(NKey nkey, byte[] input, byte[] signature) throws IOException;
}
