package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPAPI;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;

import java.util.Date;

public class BcOpenPGPAPI
        extends OpenPGPAPI
{
    @Override
    public PGPDigestCalculatorProvider getPGPDigestCalculatorProvider()
    {
        return new BcPGPDigestCalculatorProvider();
    }

    @Override
    public PGPKeyPairGeneratorProvider getPGPKeyPairGeneratorProvider()
    {
        return new BcPGPKeyPairGeneratorProvider();
    }

    @Override
    public PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        return new BcPGPContentSignerBuilderProvider(hashAlgorithmId);
    }

    @Override
    public PBESecretKeyEncryptorFactory getPBESecretKeyEncryptorFactory()
    {
        return new BcAEADSecretKeyEncryptorFactory();
    }

    @Override
    public OpenPGPV6KeyGenerator getKeyGenerator()
    {
        return new BcOpenPGPV6KeyGenerator();
    }

    @Override
    public OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
    {
        return new BcOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, aeadProtection);
    }

    @Override
    public PBESecretKeyDecryptor getSecretKeyDecryptor(char[] passphrase)
    {
        return new BcPBESecretKeyDecryptorBuilder(getPGPDigestCalculatorProvider())
                .build(passphrase);
    }
}
