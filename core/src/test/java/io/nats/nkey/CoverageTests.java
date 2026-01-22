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

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Random;

import static io.nats.nkey.NKeyConstants.NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY;
import static io.nats.nkey.NKeyProvider.getProvider;
import static org.junit.jupiter.api.Assertions.*;

public class CoverageTests {
    @Test
    public void testGetProvider() {
        NKeyProvider.clearInstance();
        System.setProperty(NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY, "io.nats.nkey.CoreNKeyProvider");
        getProvider();

        NKeyProvider.clearInstance();
        System.setProperty(NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY, "io.nats.nkey.InvalidNKeyProvider");
        //noinspection Convert2MethodRef
        RuntimeException r = assertThrows(RuntimeException.class, () -> getProvider());
        assertTrue(r.getCause() instanceof ClassNotFoundException);

        NKeyProvider.clearInstance();
        System.clearProperty(NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY);
        //noinspection Convert2MethodRef
        r = assertThrows(RuntimeException.class, () -> getProvider());
        assertTrue(r.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void testKeyWrapper() {
        CorePrivateKeyWrapper v = new CorePrivateKeyWrapper(null);
        assertEquals("EdDSA", v.getAlgorithm());
        assertEquals("PKCS#8", v.getFormat());

        CorePublicKeyWrapper u = new CorePublicKeyWrapper(null);
        assertEquals("EdDSA", u.getAlgorithm());
        assertEquals("PKCS#8", u.getFormat());
    }

    @Test
    public void testSetRandoms() {
        NKeyProvider p = new NKeyProvider() {
            @Override
            public NKey createPair(NKeyType type, byte[] seed) {
                return null;
            }

            @Override
            public KeyPair getKeyPair(NKey nkey) {
                return null;
            }

            @Override
            public byte[] sign(NKey nkey, byte[] input) {
                return new byte[0];
            }

            @Override
            public boolean verify(NKey nkey, byte[] input, byte[] signature) {
                return false;
            }
        };
        SecureRandom s1 = p.getSecureRandom();
        assertNotNull(s1);

        SecureRandom s2 = new SecureRandom();
        p.setSecureRandom(s2);

        SecureRandom s3 = p.getSecureRandom();
        assertNotNull(s3);
        assertNotEquals(s1, s3);
        assertEquals(s2, s3);

        Random r1 = p.getRandom();
        assertNotNull(r1);

        Random r2 = new Random();
        p.setRandom(r2);

        Random r3 = p.getRandom();
        assertNotNull(r3);
        assertNotEquals(r1, r3);
        assertEquals(r2, r3);
    }
}
