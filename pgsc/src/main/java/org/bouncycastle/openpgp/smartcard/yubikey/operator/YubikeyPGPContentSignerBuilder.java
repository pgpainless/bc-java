package org.bouncycastle.openpgp.smartcard.yubikey.operator;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCard;
import org.bouncycastle.pqc.crypto.DigestUtils;

import java.io.IOException;
import java.io.OutputStream;

public class YubikeyPGPContentSignerBuilder
        implements PGPContentSignerBuilder
{
    private final OpenPGPKey.OpenPGPSecretKey signingKey;
    private final YubikeyOpenPGPSmartCard smartCard;
    private final KeyPassphraseProvider userPinProvider;
    private final int hashAlgorithmId;
    private final PGPDigestCalculatorProvider digestCalculatorProvider;

    public YubikeyPGPContentSignerBuilder(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            YubikeyOpenPGPSmartCard smartCard,
            KeyPassphraseProvider userPinProvider,
            PGPDigestCalculatorProvider digestCalculatorProvider,
            int hashAlgorithmId)
    {
        this.signingKey = signingKey;
        this.smartCard = smartCard;
        this.userPinProvider = userPinProvider;
        this.digestCalculatorProvider = digestCalculatorProvider;
        this.hashAlgorithmId = hashAlgorithmId;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey)
            throws PGPException
    {
        if (privateKey.getKeyID() != signingKey.getPGPSecretKey().getKeyID())
        {
            throw new PGPException("private key does not match signing key");
        }
        return build(signatureType);
    }

    @Override
    public PGPContentSigner build(int signatureType)
            throws PGPException
    {
        PGPDigestCalculator digestCalc = digestCalculatorProvider.get(hashAlgorithmId);
        OutputStream digestOut = digestCalc.getOutputStream();

        return new PGPContentSigner()
        {
            @Override
            public OutputStream getOutputStream()
            {
                return digestOut;
            }

            @Override
            public byte[] getSignature()
            {
                char[] pin;
                try
                {
                    pin = requireUserPin();
                }
                catch (KeyPassphraseException e)
                {
                    throw new IllegalStateException("No user PIN provided.", e);
                }

                byte[] digest;
                try
                {
                    digest = encodeHashValue(getDigest());
                }
                catch (IOException | PGPException e)
                {
                    throw new RuntimeException(e);
                }
                try (OpenPgpSession session = smartCard.openSession())
                {
                    session.verifyUserPin(pin, false);
                    return session.sign(digest);
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new RuntimeException("Exception communicating with card. Cannot sign.", e);
                }
                catch (InvalidPinException e)
                {
                    throw new IllegalStateException("Wrong PIN for card " + smartCard.getSerialNumber(),
                            new KeyPassphraseException(signingKey, e));
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
                return hashAlgorithmId;
            }

            @Override
            public int getKeyAlgorithm()
            {
                return signingKey.getAlgorithm();
            }

            @Override
            public long getKeyID()
            {
                return signingKey.getKeyIdentifier().getKeyId();
            }

            private byte[] encodeHashValue(byte[] digest)
                    throws PGPException, IOException
            {
                int alg = getKeyAlgorithm();
                // RSA requires to EMSA-PKCS1-v1_5-ENCODE the hash value
                // see https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.1
                if (alg == PublicKeyAlgorithmTags.RSA_GENERAL || alg == PublicKeyAlgorithmTags.RSA_SIGN)
                {
                    String digestName = PGPUtil.getDigestName(hashAlgorithmId);
                    ASN1ObjectIdentifier hashOID = DigestUtils.getDigestOid(digestName);
                    AlgorithmIdentifier algId = new AlgorithmIdentifier(hashOID, DERNull.INSTANCE);
                    DigestInfo info = new DigestInfo(algId, digest);
                    return info.getEncoded(ASN1Encoding.DER);
                }
                return digest;
            }
        };
    }

    /**
     * Fetch the card's user PIN. The returned array is the caller's to zeroize once the card has
     * verified it.
     */
    private char[] requireUserPin()
            throws KeyPassphraseException
    {
        char[] pin = userPinProvider.getKeyPassword(signingKey);
        if (pin == null || pin.length == 0)
        {
            throw new KeyPassphraseException(signingKey, new IllegalStateException("PIN required."));
        }
        return pin;
    }
}
