// Copyright 2025 The NATS Authors
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

import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

class KeyCodec {
    // This value can be obtained on Java 15+ with
    // KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate().getEncoded()
    // which returns this + private key bytes.
    //  48 - sequence tag
    //  46 - length
    //   2 - integer tag
    //   1 - length
    //   0 - version - PKCS#8v1
    //  48 - sequence tag
    //   5 - length
    //   6 - OID tag
    //   3 - length
    //  43 - 1st byte of Ed25519 OID - "1.3.101.112"
    // 101 - 2nd byte
    // 112 - 3rd byte
    //   4 - octet string tag
    //  34 - length
    //   4 - octet string tag
    //  32 - length
    private static final byte[] PRIVATE_KEY_PREFIX = new byte[]{48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32};
    // This value can be obtained on Java 15+ with
    // KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded()
    // which returns this + public key bytes.
    //  48 - sequence tag
    //  42 - length
    //  48 - sequence tag
    //   5 - length
    //   6 - OID tag
    //   3 - length
    //  43 - 1st byte of Ed25519 OID - "1.3.101.112"
    // 101 - 2nd byte
    // 112 - 3rd byte
    //   3 - bit string tag
    //  33 - length
    //   0 - number of unused bits in final byte
    private static final byte[] PUBLIC_KEY_PREFIX = new byte[]{48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0};

    static byte[] publicKeyToPubBytes(PublicKey key) {
        if (!"Ed25519".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("Only Ed25519 keys are supported");
        }
        if (!"X.509".equals(key.getFormat())) {
            throw new IllegalArgumentException("Only X509 encoded keys are supported");
        }

        byte[] encoded = key.getEncoded();
        if (encoded.length != PUBLIC_KEY_PREFIX.length + 32) {
            throw new IllegalArgumentException("Unsupported Ed25519 public key encoding");
        }
        for (int i = 0; i < PUBLIC_KEY_PREFIX.length; i++) {
            if (encoded[i] != PUBLIC_KEY_PREFIX[i]) {
                throw new IllegalArgumentException("Unsupported Ed25519 public key encoding");
            }
        }

        return Arrays.copyOfRange(encoded, PUBLIC_KEY_PREFIX.length, encoded.length);
    }

    static PKCS8EncodedKeySpec seedBytesToKeySpec(byte[] seedBytes) {
        byte[] pkcs8Bytes = concat(PRIVATE_KEY_PREFIX, seedBytes);
        return new PKCS8EncodedKeySpec(pkcs8Bytes);
    }

    static X509EncodedKeySpec pubBytesToKeySpec(byte[] pubBytes) {
        byte[] x509Bytes = concat(PUBLIC_KEY_PREFIX, pubBytes);
        return new X509EncodedKeySpec(x509Bytes);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
