package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class HMACPublicBCPGKey
        extends PersistentSymmetricBCPGPublicKey
{
    private final int hashAlgorithmId;
    private final byte[] fingerprintSeed;

    public HMACPublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        this.hashAlgorithmId = in.read();
        this.fingerprintSeed = expectSeed(in.readAll());
    }

    public HMACPublicBCPGKey(int hashAlgorithmId,
                             byte[] fingerprintSeed)
            throws IOException
    {
        this.hashAlgorithmId = hashAlgorithmId;
        this.fingerprintSeed = expectSeed(fingerprintSeed);
    }

    public HMACPublicBCPGKey(int hashAlgorithmId)
    {
        this.hashAlgorithmId = hashAlgorithmId;
        this.fingerprintSeed = createSeed();
    }

    public int getHashAlgorithmId()
    {
        return hashAlgorithmId;
    }

    @Override
    public byte[] getFingerprintSeed()
    {
        return Arrays.clone(fingerprintSeed);
    }

    @Override
    public void encode(BCPGOutputStream out)
            throws IOException
    {
        out.write(hashAlgorithmId);
        out.write(fingerprintSeed);
    }
}
