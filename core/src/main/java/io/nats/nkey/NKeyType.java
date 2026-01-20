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

import org.jspecify.annotations.Nullable;

import static io.nats.nkey.NKeyConstants.*;

/**
 * NKeys use a prefix byte to indicate their intended owner: 'N' = server, 'C' =
 * cluster, 'A' = account, and 'U' = user. 'P' is used for private keys. The
 * NKey class formalizes these into the enum Type.
 */
public enum NKeyType {
    /**
     * A user NKey.
     */
    USER(PREFIX_BYTE_USER),
    /**
     * An account NKey.
     */
    ACCOUNT(PREFIX_BYTE_ACCOUNT),
    /**
     * A server NKey.
     */
    SERVER(PREFIX_BYTE_SERVER),
    /**
     * An operator NKey.
     */
    OPERATOR(PREFIX_BYTE_OPERATOR),
    /**
     * A cluster NKey.
     */
    CLUSTER(PREFIX_BYTE_CLUSTER),
    /**
     * A private NKey.
     */
    PRIVATE(PREFIX_BYTE_PRIVATE);

    public final int prefix;

    NKeyType(int prefix) {
        this.prefix = prefix;
    }

    public static @Nullable NKeyType fromPrefix(int prefix) {
        switch (prefix) {
            case PREFIX_BYTE_ACCOUNT:
            case PREFIX_BYTE_PRIVATE:  return ACCOUNT;
            case PREFIX_BYTE_SERVER:   return SERVER;
            case PREFIX_BYTE_USER:     return USER;
            case PREFIX_BYTE_CLUSTER:  return CLUSTER;
            case PREFIX_BYTE_OPERATOR: return OPERATOR;
        }
        return null;
    }
}
