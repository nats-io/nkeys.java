// Copyright 2025-2026 The NATS Authors
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

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.security.PrivateKey;

class CorePrivateKeyWrapper extends KeyWrapper implements PrivateKey {

    final Ed25519PrivateKeyParameters privateKey;

    public CorePrivateKeyWrapper(Ed25519PrivateKeyParameters privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] getEncoded() {
        return privateKey.getEncoded();
    }
}
