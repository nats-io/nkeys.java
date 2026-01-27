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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Random;

import static io.nats.nkey.NKeyConstants.*;
import static io.nats.nkey.NKeyProviderUtils.*;

/**
 * The NKeyProvider is the central object in this package.
 * It provides the base to use a specific security library to implement the requirements for NKeys
 */
@NullMarked
public abstract class NKeyProvider {

    @Nullable
    private static NKeyProvider NKEY_PROVIDER_INSTANCE;

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
     * The default constructor does nothing
     */
    protected NKeyProvider() {}

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
     * @throws IllegalAccessException if this {@code Constructor} object
     *         is enforcing Java language access control and the underlying
     *         constructor is inaccessible.
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

    /**
     * the variable used to hold the SecureRandom
     */
    @Nullable
    private SecureRandom secureRandom;

    /**
     * the variable used to hold the insecure Random
     */
    @Nullable
    private Random random;

    /**
     * Set the SecureRandom
     * @param secureRandom the SecureRandom
     */
    protected void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    /**
     * Set the insecure Random
     * @param random the Random
     */
    protected void setRandom(Random random) {
        this.random = random;
    }

    /**
     * Get the SecureRandom instance for this provider.
     * @return the SecureRandom
     */
    public SecureRandom getSecureRandom() {
        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }
        return secureRandom;
    }

    /**
     * Get the insecure Random instance for this provider.
     * @return the Random
     */
    public Random getRandom() {
        if (random == null) {
            byte[] bytes = getSecureRandom().generateSeed(8);
            ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE);
            buffer.put(bytes);
            buffer.flip();// need flip
            random = new Random(buffer.getLong()); // seed with 8 bytes (64 bits)
        }
        return random;
    }

    /**
     * Create an NKey of the NKeyType with a generated seed
     * @param type the NKeyType
     * @return the NKey
     */
    protected NKey createNKey(NKeyType type) {
        byte[] seed = new byte[ED25519_SEED_SIZE];
        getSecureRandom().nextBytes(seed);
        return createNKey(type, seed);
    }

    /**
     * Create an NKey of the NKeyType using the provided seed
     * @param type the NKeyType
     * @param seed the seed
     * @return the NKey
     */
    protected abstract NKey createNKey(NKeyType type, byte[] seed);

    /**
     * Create an Account NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     */
    public NKey createAccount() {
        return createNKey(NKeyType.ACCOUNT);
    }

    /**
     * Create a Cluster NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     */
    public NKey createCluster() {
        return createNKey(NKeyType.CLUSTER);
    }

    /**
     * Create an Operator NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     */
    public NKey createOperator() {
        return createNKey(NKeyType.OPERATOR);
    }

    /**
     * Create a Server NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     */
    public NKey createServer() {
        return createNKey(NKeyType.SERVER);
    }

    /**
     * Create a User NKey from the provided random number generator.
     * If no random is provided, SecureRandom() will be used to create one.
     * The new NKey contains the private seed, which should be saved in a secure location.
     * @return the new NKey
     */
    public NKey createUser() {
        return createNKey(NKeyType.USER);
    }

    /**
     * Create an NKey object from the encoded public key. This NKey can be used for verification but not for signing.
     * @param publicKey the string encoded public key
     * @return the new NKey
     */
    public NKey fromPublicKey(char[] publicKey) {
        byte[] raw = nkeyDecode(publicKey);
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
            return createNKey(t, decoded.bytes);
        }
        catch (IllegalArgumentException e) {
            throw e;
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Bad seed value", e);
        }
    }

    /**
     * A Java security keypair that represents this NKey in Java security form.
     * @param nkey the NKey to get the KeyPair from
     * @return A Java security keypair that represents this NKey in Java security form.
     */
    public abstract KeyPair getKeyPair(NKey nkey);

    /**
     * Sign arbitrary binary input.
     * @param nkey the NKey to use to sign
     * @param input the bytes to sign
     * @return the signature for the input from the NKey
     */
    public abstract byte[] sign(NKey nkey, byte[] input);

    /**
     * Verify a signature.
     * @param nkey      the NKey to use to verify
     * @param input     the bytes that were signed
     * @param signature the bytes for the signature
     * @return true if the signature matches this keys signature for the input.
     */
    public abstract boolean verify(NKey nkey, byte[] input, byte[] signature);
}
