package org.bouncycastle.openpgp.api.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPAPI;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaCFBSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.security.Provider;
import java.util.Date;

public class JcaOpenPGPAPI
        extends OpenPGPAPI
{
    private final Provider provider;

    public JcaOpenPGPAPI(Provider provider)
    {
        this.provider = provider;
    }

    @Override
    public PGPKeyPairGeneratorProvider getPGPKeyPairGeneratorProvider()
    {
        return new JcaPGPKeyPairGeneratorProvider().setProvider(provider);
    }

    @Override
    public PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        return new JcaPGPContentSignerBuilderProvider(hashAlgorithmId)
                .setSecurityProvider(provider)
                .setDigestProvider(provider);
    }

    @Override
    public PBESecretKeyEncryptorFactory getPBESecretKeyEncryptorFactory()
            throws PGPException
    {
        return new JcaCFBSecretKeyEncryptorFactory().setProvider(provider);
    }

    @Override
    public OpenPGPV6KeyGenerator getKeyGenerator()
            throws PGPException
    {
        return new JcaOpenPGPV6KeyGenerator(provider);
    }

    @Override
    public OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
            throws PGPException
    {
        return new JcaOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, provider, aeadProtection);
    }

    @Override
    public PGPDigestCalculatorProvider getPGPDigestCalculatorProvider()
            throws PGPException
    {
        return new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(provider)
                .build();
    }

    @Override
    public PBESecretKeyDecryptor getSecretKeyDecryptor(char[] passphrase)
            throws PGPException
    {
        return new JcePBESecretKeyDecryptorBuilder(getPGPDigestCalculatorProvider())
                .build(passphrase);
    }
}
