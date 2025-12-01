package io.nats.nkey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

/**
 * Wraps construction of {@link BouncyCastleProvider} class to defer loading of the class.
 * That allows users to exclude the BouncyCastle dependency if they want to use another provider.
 */
class DefaultSecurityProviderFactory {
    static Provider getProvider() {
        return new BouncyCastleProvider();
    }
}
