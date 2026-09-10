package org.bouncycastle.openpgp.smartcard.operator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyConverter
{
    /**
     * Convert BCs elliptic {@link AsymmetricKeyParameter} public key into a JCA {@link PublicKey}.
     * @param keyAlgorithm OpenPGP PK algorithm ID
     * @param publicKey public key
     * @param provider provider
     * @return public key
     * @throws PGPException if the key cannot be converted
     */
    public static PublicKey convertEllipticPublicKey(int keyAlgorithm,
                                                     AsymmetricKeyParameter publicKey,
                                                     Provider provider)
            throws PGPException
    {
        if (publicKey.isPrivate())
        {
            throw new PGPException("Public key expected.");
        }

        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
            if (info == null)
            {
                throw new PGPException("Cannot create SubjectPublicKeyInfo for public key.");
            }

            KeyFactory factory;
            String algorithmName;
            switch (keyAlgorithm)
            {
                case PublicKeyAlgorithmTags.ECDH:
                    algorithmName = "ECDH";
                    break;

                case PublicKeyAlgorithmTags.ECDSA:
                    algorithmName = "ECDSA";
                    break;

                case PublicKeyAlgorithmTags.EDDSA_LEGACY:
                    algorithmName = "EDDSA";
                    break;

                case PublicKeyAlgorithmTags.X25519:
                    algorithmName = "X25519";
                    break;

                case PublicKeyAlgorithmTags.X448:
                    algorithmName = "X448";
                    break;

                case PublicKeyAlgorithmTags.Ed25519:
                    algorithmName = "Ed25519";
                    break;

                case PublicKeyAlgorithmTags.Ed448:
                    algorithmName = "Ed448";
                    break;

                default:
                    throw new PGPException("unsupported key type: " + publicKey.getClass().getName());
            }

            factory = KeyFactory.getInstance(algorithmName, provider);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(info.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            return factory.generatePublic(keySpec);
        }
        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new PGPException("Cannot convert public key", e);
        }
    }
}
