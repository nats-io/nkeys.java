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

import java.lang.reflect.Constructor;

import static io.nats.nkey.NKeyConstants.NKEY_PROVIDER_CLASS_ENVIRONMENT_VAR;
import static io.nats.nkey.NKeyConstants.NKEY_PROVIDER_CLASS_SYSTEM_PROPERTY;
import static io.nats.nkey.NKeyInternalUtils.decode;

public abstract class NKeyUtils {

    static NKeyProvider NKEY_PROVIDER_INSTANCE;

    /**
     * Get the NKeyProvider
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

                Class<?> clazz = Class.forName(className);
                Constructor<?> constructor = clazz.getConstructor();
                NKEY_PROVIDER_INSTANCE = (NKeyProvider) constructor.newInstance();
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return NKEY_PROVIDER_INSTANCE;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is an account public key
     * @throws IllegalArgumentException if is not a valid Account key
     */
    public static boolean isValidPublicAccountKey(char[] src) {
        decode(NKeyType.ACCOUNT, src);
        return true;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a cluster public key
     * @throws IllegalArgumentException if is not a valid Cluster key
     */
    public static boolean isValidPublicClusterKey(char[] src) {
        decode(NKeyType.CLUSTER, src);
        return true;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is an operator public key
     * @throws IllegalArgumentException if is not a valid Operator key
     */
    public static boolean isValidPublicOperatorKey(char[] src) {
        decode(NKeyType.OPERATOR, src);
        return true;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a server public key
     * @throws IllegalArgumentException if is not a valid Server key
     */
    public static boolean isValidPublicServerKey(char[] src) {
        decode(NKeyType.SERVER, src);
        return true;
    }

    /**
     * @param src the encoded public key
     * @return true if the public key is a user public key
     * @throws IllegalArgumentException if is not a valid User key
     */
    public static boolean isValidPublicUserKey(char[] src) {
        decode(NKeyType.USER, src);
        return true;
    }
}

