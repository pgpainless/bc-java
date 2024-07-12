package org.bouncycastle.bcpg;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * Abstract public key implementation for persistent symmetric keys in OpenPGP.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-00.html">
 *     Persistent Symmetric Keys in OpenPGP</a>
 */
public abstract class PersistentSymmetricBCPGPublicKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int SEED_LENGTH = 32;

    public abstract byte[] getFingerprintSeed();

    @Override
    public String getFormat() {
        return "PGP";
    }

    @Override
    public byte[] getEncoded()
    {
        try
        {
            return super.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    /**
     * Check that the passed in seed array consists of 32 bytes.
     * @param seed seed
     * @return sanitized seed
     */
    protected static byte[] expectSeed(byte[] seed)
            throws IOException
    {
        if (seed.length != SEED_LENGTH)
        {
            throw new IOException("Expected " + SEED_LENGTH + " octets of fingerprint seed, but got " + seed.length);
        }
        return Arrays.clone(seed);
    }

    /**
     * Generate 32 random octets to be used to seed the fingerprint calculation.
     * @return 32 seed bytes
     */
    protected static byte[] createSeed()
    {
        byte[] seed = new byte[SEED_LENGTH];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(seed);
        return seed;
    }

}
