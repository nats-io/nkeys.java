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

/**
 * A decoded version of the NKey seed
 * Used for internal and NKeyProvider implementations, not really intended to be public
 */
public class NKeyDecodedSeed {
    /**
     * The prefix
     */
    public final int prefix;

    /**
     * The bytes
     */
    public final byte[] bytes;

    /**
     * Construct an NKeyDecodedSeed
     * @param prefix the prefix
     * @param bytes the bytes
     */
    public NKeyDecodedSeed(int prefix, byte[] bytes) {
        this.prefix = prefix;
        this.bytes = bytes;
    }
}
