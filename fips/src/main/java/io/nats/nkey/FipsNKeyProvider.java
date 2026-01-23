package io.nats.nkey;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jspecify.annotations.NullMarked;

import java.security.*;

@NullMarked
public class FipsNKeyProvider extends NKeyProvider {
    static {
        // Register BC-FIPS provider
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public FipsNKeyProvider() {
        try {
            setSecureRandom(SecureRandom.getInstance("DEFAULT", "BCFIPS"));
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NKey createNKey(NKeyType type, byte[] seed) {
        throw new UnsupportedOperationException("createPair not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair getKeyPair(NKey nkey) {
        nkey.ensurePair();
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
