package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;

public class JcePBEProtectionRemoverFactory
    implements PBEProtectionRemoverFactory
{
    private final char[] passPhrase;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private PGPDigestCalculatorProvider calculatorProvider;

    private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;
    private JcePBESecretKeyDecryptorBuilder decryptorBuilder;

    public JcePBEProtectionRemoverFactory(char[] passPhrase)
    {
        this.passPhrase = passPhrase;
        this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
        this.decryptorBuilder = new JcePBESecretKeyDecryptorBuilder(calculatorProvider);
    }

    public JcePBEProtectionRemoverFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
        this.decryptorBuilder = new JcePBESecretKeyDecryptorBuilder(calculatorProvider);
    }

    public JcePBEProtectionRemoverFactory setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }
        decryptorBuilder.setProvider(provider);
        return this;
    }

    public JcePBEProtectionRemoverFactory setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(providerName);
        }
        decryptorBuilder.setProvider(providerName);
        return this;
    }

    public PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException
    {
        if (calculatorProvider == null)
        {
            calculatorProvider = calculatorProviderBuilder.build();
        }

        if (protection.indexOf("ocb") >= 0)
        {
            return new PGPSecretKeyDecryptorWithAAD(passPhrase, calculatorProvider)
            {
                @Override
                public byte[] recoverKeyData(int encAlgorithm, int aeadAlgorithm, byte[] s2kKey, byte[] iv, int packetTag, int keyVersion, byte[] keyData, byte[] pubkeyData) throws PGPException {
                    return decryptorBuilder.build(passPhrase).recoverKeyData(encAlgorithm, aeadAlgorithm, s2kKey, iv, packetTag, keyVersion, keyData, pubkeyData);
                }

                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] aad, byte[] keyData, int keyOff, int keyLen)
                    throws PGPException
                {
                    try
                    {
                        Cipher c;
                        c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/OCB/NoPadding");
                        c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new AEADParameterSpec(iv, 128, aad));
                        return c.doFinal(keyData, keyOff, keyLen);
                    }
                    catch (IllegalBlockSizeException e)
                    {
                        throw new PGPException("illegal block size: " + e.getMessage(), e);
                    }
                    catch (BadPaddingException e)
                    {
                        throw new PGPException("bad padding: " + e.getMessage(), e);
                    }
                    catch (InvalidAlgorithmParameterException e)
                    {
                        throw new PGPException("invalid parameter: " + e.getMessage(), e);
                    }
                    catch (InvalidKeyException e)
                    {
                        throw new PGPException("invalid key: " + e.getMessage(), e);
                    }
                }
            };
        }
        else
        {
            return decryptorBuilder.build(passPhrase);
        }
    }
}
