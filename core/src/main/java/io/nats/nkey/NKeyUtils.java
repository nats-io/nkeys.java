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

import static io.nats.nkey.NKeyInternalUtils.decode;

/**
 * General Utils
 */
public abstract class NKeyUtils {
    private NKeyUtils() {} /* ensures cannot be constructed */

    /**
     * Do the characters represent a valid public account key
     * @param src the encoded public key
     * @return true if the public key is an account public key
     * @throws IllegalArgumentException if is not a valid Account key
     */
    public static boolean isValidPublicAccountKey(char[] src) {
        decode(NKeyType.ACCOUNT, src);
        return true;
    }

    /**
     * Do the characters represent a valid public cluster key
     * @param src the encoded public key
     * @return true if the public key is a cluster public key
     * @throws IllegalArgumentException if is not a valid Cluster key
     */
    public static boolean isValidPublicClusterKey(char[] src) {
        decode(NKeyType.CLUSTER, src);
        return true;
    }

    /**
     * Do the characters represent a valid public operator key
     * @param src the encoded public key
     * @return true if the public key is an operator public key
     * @throws IllegalArgumentException if is not a valid Operator key
     */
    public static boolean isValidPublicOperatorKey(char[] src) {
        decode(NKeyType.OPERATOR, src);
        return true;
    }

    /**
     * Do the characters represent a valid public server key
     * @param src the encoded public key
     * @return true if the public key is a server public key
     * @throws IllegalArgumentException if is not a valid Server key
     */
    public static boolean isValidPublicServerKey(char[] src) {
        decode(NKeyType.SERVER, src);
        return true;
    }

    /**
     * Do the characters represent a valid public user key
     * @param src the encoded public key
     * @return true if the public key is a user public key
     * @throws IllegalArgumentException if is not a valid User key
     */
    public static boolean isValidPublicUserKey(char[] src) {
        decode(NKeyType.USER, src);
        return true;
    }
}

