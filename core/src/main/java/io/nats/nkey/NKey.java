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

import java.security.KeyPair;
import java.util.Arrays;

import static io.nats.nkey.NKeyConstants.ED25519_SEED_SIZE;
import static io.nats.nkey.NKeyInternalUtils.*;

/**
 * The NKey class
 */
public class NKey {

    private final NKeyProvider provider;

    /**
     * The seed or private key per the Ed25519 spec, encoded with encodeSeed.
     */
    private final char[] privateKeyAsSeed;

    /**
     * The public key, may be null. Used for public only NKeys.
     */
    private final char[] publicKey;

    private final NKeyType type;

    /**
     * Construct an NKey
     * @param provider the NKeyProvider
     * @param type the NKeyType
     * @param publicKey the public key characters
     * @param privateKey the private key characters
     */
    public NKey(NKeyProvider provider, NKeyType type, char[] publicKey, char[] privateKey) {
        this.provider = provider;
        this.type = type;
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
                privateKeyAsSeed[i] = (char)(provider.getRandom().nextInt(26) + 'a');
            }
            Arrays.fill(privateKeyAsSeed, '\0');
        }
        if (publicKey != null) {
            for (int i=0; i< publicKey.length ; i++) {
                publicKey[i] = (char)(provider.getRandom().nextInt(26) + 'a');
            }
            Arrays.fill(publicKey, '\0');
        }
    }

    /**
     * Get the string encoded seed for this NKey
     * @return the seed characters
     */
    public char[] getSeed() {
        NKeyDecodedSeed decoded = getDecodedSeed();
        byte[] seedBytes = new byte[ED25519_SEED_SIZE];
        System.arraycopy(decoded.bytes, 0, seedBytes, 0, seedBytes.length);
        try {
            return encodeSeed(NKeyType.fromPrefix(decoded.prefix), seedBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create seed.", e);
        }
    }

    /**
     * Ensures that the NKey is a pair, not public only
     * @throws IllegalStateException if the NKey is a public only key
     */
    public void ensurePair() {
        if (isPublicOnly()) {
            throw new IllegalStateException("Public-only NKey");
        }
    }

    /**
     * Get the decoded seed
     * @return the decoded seed
     * @throws IllegalStateException if the NKey is a public only key
     */
    public NKeyDecodedSeed getDecodedSeed() {
        ensurePair();
        return decodeSeed(privateKeyAsSeed);
    }

    /**
     * Does this NKey represent both the public and private key
     * @return true if is a pair
     */
    public boolean isPair() {
        return privateKeyAsSeed != null;
    }

    /**
     * Does this NKey represent only the public key half,
     * meaning does not have the private key half
     * @return true if is public only
     */
    public boolean isPublicOnly() {
        return privateKeyAsSeed == null;
    }

    /**
     * Get the encoded public key for this NKey
     * @return the encoded characters
     */
    public char[] getPublicKey() {
        if (publicKey != null) {
            return publicKey;
        }
        return encode(type, getKeyPair().getPublic().getEncoded());
    }

    /**
     * Get the encoded private key for this NKey
     * @return the encoded characters
     */
    public char[] getPrivateKey() {
        NKeyDecodedSeed decoded = getDecodedSeed();
        return encode(NKeyType.PRIVATE, decoded.bytes);
    }

    /**
     * Get the Java security keypair that represents this NKey in Java security form.
     * @return the KeyPair
     */
    public KeyPair getKeyPair() {
        ensurePair();
        return provider.getKeyPair(this);
    }

    /**
     * Get the NKeyType of this NKey
     * @return the NKeyType
     */
    public NKeyType getType() {
        return type;
    }

    /**
     * Sign arbitrary binary input.
     * @param input the bytes to sign
     * @return the signature for the input from the NKey
     */
    public byte[] sign(byte[] input) {
        return provider.sign(this, input);
    }

    /**
     * Verify a signature.
     * @param input     the bytes that were signed
     * @param signature the bytes for the signature
     * @return true if the signature matches this keys signature for the input.
     */
    public boolean verify(byte[] input, byte[] signature) {
        return provider.verify(this, input, signature);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

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

