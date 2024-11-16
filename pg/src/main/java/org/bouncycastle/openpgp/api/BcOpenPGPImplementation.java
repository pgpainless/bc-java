package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;

import java.io.InputStream;

public class BcOpenPGPImplementation
        extends OpenPGPImplementation
{
    @Override
    public PGPObjectFactory objectFactory(InputStream inputStream)
    {
        return new BcPGPObjectFactory(inputStream);
    }

    @Override
    public PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider()
    {
        return new BcPGPContentVerifierBuilderProvider();
    }

    @Override
    public PBESecretKeyDecryptorBuilderProvider pbeSecretKeyDecryptorBuilderProvider()
    {
        return new BcPBESecretKeyDecryptorBuilderProvider();
    }

    @Override
    public PGPDataEncryptorBuilder pgpDataEncryptorBuilder(int symmetricKeyAlgorithm)
    {
        return new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm);
    }

    @Override
    public PublicKeyKeyEncryptionMethodGenerator publicKeyKeyEncryptionMethodGenerator(PGPPublicKey encryptionSubkey)
    {
        return new BcPublicKeyKeyEncryptionMethodGenerator(encryptionSubkey);
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] passphrase)
    {
        return new BcPBEKeyEncryptionMethodGenerator(passphrase);
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] passphrase, S2K.Argon2Params argon2Params)
    {
        return new BcPBEKeyEncryptionMethodGenerator(passphrase, argon2Params);
    }

    @Override
    public PGPContentSignerBuilder pgpContentSignerBuilder(int algorithm, int hashAlgorithm)
    {
        return new BcPGPContentSignerBuilder(algorithm, hashAlgorithm);
    }

    @Override
    public PBEDataDecryptorFactory pbeDataDecryptorFactory(char[] passphrase)
            throws PGPException
    {
        return new BcPBEDataDecryptorFactory(passphrase, pgpDigestCalculatorProvider());
    }

    @Override
    public SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory(PGPSessionKey sessionKey)
    {
        return new BcSessionKeyDataDecryptorFactory(sessionKey);
    }

    @Override
    public PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory(PGPPrivateKey privateKey)
    {
        return new BcPublicKeyDataDecryptorFactory(privateKey);
    }

    @Override
    public PGPDigestCalculatorProvider pgpDigestCalculatorProvider()
            throws PGPException
    {
        return new BcPGPDigestCalculatorProvider();
    }
}
