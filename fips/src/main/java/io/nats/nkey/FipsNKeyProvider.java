package io.nats.nkey;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jspecify.annotations.NullMarked;
import sun.security.jca.JCAUtil;

import java.security.KeyPair;
import java.security.Security;

@NullMarked
public class FipsNKeyProvider extends NKeyProvider {
    static {
        // Register BC-FIPS provider
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public FipsNKeyProvider() {
        setSecureRandom(JCAUtil.getDefSecureRandom());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NKey createPair(NKeyType type, byte[] seed) {
        throw new UnsupportedOperationException("createPair not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair getKeyPair(NKey nkey) {
        throw new UnsupportedOperationException("getKeyPair not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] sign(NKey nkey, byte[] input) {
        throw new UnsupportedOperationException("sign not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(NKey nkey, byte[] input, byte[] signature) {
        throw new UnsupportedOperationException("verify not supported yet.");
    }
}
