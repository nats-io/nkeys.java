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

package nats.io.nkeys;

import static nats.io.nkeys.Common.*;

/**
 * NKeys use a prefix byte to indicate their intended owner: 'N' = server, 'C' =
 * cluster, 'A' = account, and 'U' = user. 'P' is used for private keys. The
 * NKey class formalizes these into the enum NKeyType.
 */
public enum NKeyType {
    /** A user NKey. */
    USER(PREFIX_BYTE_USER),
    /** An account NKey. */
    ACCOUNT(PREFIX_BYTE_ACCOUNT),
    /** A server NKey. */
    SERVER(PREFIX_BYTE_SERVER),
    /** An operator NKey. */
    OPERATOR(PREFIX_BYTE_OPERATOR),
    /** A cluster NKey. */
    CLUSTER(PREFIX_BYTE_CLUSTER),
    /** A private NKey. */
    PRIVATE(PREFIX_BYTE_PRIVATE);

    public final int prefix;

    NKeyType(int prefix) {
        this.prefix = prefix;
    }

    public static NKeyType fromPrefix(int prefix) {
        if (prefix == PREFIX_BYTE_ACCOUNT) {
            return ACCOUNT;
        } else if (prefix == PREFIX_BYTE_SERVER) {
            return SERVER;
        } else if (prefix == PREFIX_BYTE_USER) {
            return USER;
        } else if (prefix == PREFIX_BYTE_CLUSTER) {
            return CLUSTER;
        } else if (prefix == PREFIX_BYTE_PRIVATE) {
            return ACCOUNT;
        } else if (prefix == PREFIX_BYTE_OPERATOR) {
            return OPERATOR;
        }

        throw new IllegalArgumentException("Unknown prefix");
    }
}
