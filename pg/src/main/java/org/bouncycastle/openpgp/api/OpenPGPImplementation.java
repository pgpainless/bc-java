package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
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

import java.io.InputStream;

public abstract class OpenPGPImplementation
{
    public abstract PGPObjectFactory pgpObjectFactory(InputStream inputStream);

    public abstract PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider();

    public abstract PBESecretKeyDecryptorBuilderProvider pbeSecretKeyDecryptorBuilderProvider();

    public abstract PGPDataEncryptorBuilder pgpDataEncryptorBuilder(int symmetricKeyAlgorithm);

    public abstract PublicKeyKeyEncryptionMethodGenerator publicKeyKeyEncryptionMethodGenerator(PGPPublicKey encryptionSubkey);

    public abstract PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] passphrase);

    public abstract PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] passphrase, S2K.Argon2Params argon2Params);

    public abstract PGPContentSignerBuilder pgpContentSignerBuilder(int algorithm, int hashAlgorithm);

    public abstract PBEDataDecryptorFactory pbeDataDecryptorFactory(char[] passphrase) throws PGPException;

    public abstract SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory(PGPSessionKey sessionKey);

    public abstract PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory(PGPPrivateKey privateKey);

    public abstract PGPDigestCalculatorProvider pgpDigestCalculatorProvider() throws PGPException;
}
