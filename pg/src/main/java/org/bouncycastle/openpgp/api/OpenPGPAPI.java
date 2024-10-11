package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;

import java.util.Date;

public abstract class OpenPGPAPI
{
    public abstract PGPKeyPairGeneratorProvider getPGPKeyPairGeneratorProvider()
            throws PGPException;

    public abstract PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(int hashAlgorithmId)
            throws PGPException;

    public abstract PBESecretKeyEncryptorFactory getPBESecretKeyEncryptorFactory()
            throws PGPException;

    public abstract OpenPGPV6KeyGenerator getKeyGenerator()
            throws PGPException;

    public abstract OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
            throws PGPException;

    public abstract PGPDigestCalculatorProvider getPGPDigestCalculatorProvider()
            throws PGPException;

    public abstract PBESecretKeyDecryptor getSecretKeyDecryptor(char[] passphrase)
            throws PGPException;
}
