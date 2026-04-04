package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;

public class MLKEM768X25519PublicKeyParameters
        extends MLKEMECCKeyParameters<X25519PublicKeyParameters, MLKEMPublicKeyParameters>
{
    public static final int MLKEM768_SIZE = 1184;
    public static final int KEY_SIZE = X25519.POINT_SIZE + MLKEM768_SIZE;

    public MLKEM768X25519PublicKeyParameters(byte[] buf)
    {
        super(false,
                parseECCComponent(validate(buf, KEY_SIZE)),
                parseMlKemComponent(buf));
    }

    public MLKEM768X25519PublicKeyParameters(InputStream input) throws IOException
    {
        this(Streams.readAll(input));
    }

    private MLKEM768X25519PublicKeyParameters(
            X25519PublicKeyParameters x25519PublicKey,
            MLKEMPublicKeyParameters mlKemPublicKey)
    {
        super(false, x25519PublicKey, mlKemPublicKey);
    }

    @Override
    protected byte[] getEncodedEccKey()
    {
        return getEccKeyParameter().getEncoded();
    }

    @Override
    protected byte[] getEncodedMlKemKey()
    {
        return getMlKemKeyParameter().getEncoded();
    }

    @Override
    protected int getEccKeySize()
    {
        return X25519PublicKeyParameters.KEY_SIZE;
    }

    @Override
    protected int getMlKemKeySize()
    {
        return MLKEM768_SIZE;
    }

    private static X25519PublicKeyParameters parseECCComponent(byte[] bytes)
    {
        byte[] x25519 = new byte[X25519.POINT_SIZE];
        System.arraycopy(bytes, 0, x25519, 0, x25519.length);
        return new X25519PublicKeyParameters(x25519);
    }

    private static MLKEMPublicKeyParameters parseMlKemComponent(byte[] bytes)
    {
        byte[] mlkem = new byte[MLKEM768_SIZE];
        System.arraycopy(bytes, X25519.POINT_SIZE, mlkem, 0, mlkem.length);
        return new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, mlkem);
    }
}
