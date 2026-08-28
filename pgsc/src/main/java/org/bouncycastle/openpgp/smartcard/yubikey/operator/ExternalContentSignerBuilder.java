package org.bouncycastle.openpgp.smartcard.yubikey.operator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.pqc.crypto.DigestUtils;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;

public class ExternalContentSignerBuilder
        implements PGPContentSignerBuilder
{
    protected final OpenPGPHardwareKey hardwareKey;
    protected final OpenPGPKey.OpenPGPSecretKey stubKey;
    protected final KeyPassphraseProvider userPinProvider;
    protected final int hashAlgorithm;
    protected final PGPDigestCalculatorProvider digestCalculatorProvider;

    public ExternalContentSignerBuilder(
            OpenPGPHardwareKey key,
            OpenPGPKey.OpenPGPSecretKey stubKey,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithm,
            PGPDigestCalculatorProvider calculatorProvider)
    {
        this.hardwareKey = key;
        this.stubKey = stubKey;
        this.userPinProvider = userPinProvider;
        this.hashAlgorithm = hashAlgorithm;
        this.digestCalculatorProvider = calculatorProvider;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey)
            throws PGPException
    {
        if (privateKey.getKeyID() != stubKey.getPGPSecretKey().getKeyID())
        {
            throw new PGPException("private key does not match signing key");
        }
        return build(signatureType);
    }

    @Override
    public PGPContentSigner build(int signatureType)
            throws PGPException
    {
        // Not sure why, but we need to use two different calculators here, as otherwise
        //  modern ed25519 signing fails due to an additional unexpected digest update
        PGPDigestCalculator digestCalc = digestCalculatorProvider.get(hashAlgorithm);
        PGPDigestCalculator sigDigestCalc = digestCalculatorProvider.get(hashAlgorithm);

        return new PGPContentSigner()
        {
            @Override
            public OutputStream getOutputStream()
            {
                return new TeeOutputStream(digestCalc.getOutputStream(), sigDigestCalc.getOutputStream());
            }

            @Override
            public byte[] getSignature()
            {
                byte[] data = sigDigestCalc.getDigest();
                byte[] digest;
                try
                {
                    digest = encodeHashValue(data);
                }
                catch (PGPException | IOException e)
                {
                    throw new RuntimeException("Cannot encode digest value.", e);
                }

                try
                {
                    return hardwareKey.sign(userPinProvider, stubKey, digest);
                }
                catch (PGPException | CardException e)
                {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public byte[] getDigest()
            {
                return digestCalc.getDigest();
            }

            @Override
            public int getType()
            {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm()
            {
                return hashAlgorithm;
            }

            @Override
            public int getKeyAlgorithm()
            {
                return stubKey.getAlgorithm();
            }

            @Override
            public long getKeyID()
            {
                return stubKey.getKeyIdentifier().getKeyId();
            }

            /**
             * Signing with RSA expects the digest value to be DER encoded.
             *
             * @param digest raw digest
             * @return possibly encoded digest
             * @throws PGPException unknown digest
             * @throws IOException digest cannot be encoded
             */
            private byte[] encodeHashValue(byte[] digest)
                    throws PGPException, IOException
            {
                int alg = getKeyAlgorithm();
                // RSA requires to EMSA-PKCS1-v1_5-ENCODE the hash value
                // see https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.1
                if (alg == PublicKeyAlgorithmTags.RSA_GENERAL || alg == PublicKeyAlgorithmTags.RSA_SIGN)
                {
                    String digestName = PGPUtil.getDigestName(hashAlgorithm);
                    org.bouncycastle.asn1.ASN1ObjectIdentifier hashOID = DigestUtils.getDigestOid(digestName);
                    AlgorithmIdentifier algId = new AlgorithmIdentifier(hashOID, DERNull.INSTANCE);
                    DigestInfo info = new DigestInfo(algId, digest);
                    return info.getEncoded(ASN1Encoding.DER);
                }
                return digest;
            }
        };
    }
}
