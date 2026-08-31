package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Integers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * In-memory stand-in for an OpenPGP smart card, backed by ordinary software keys.
 * <p>
 * <b>Test and development use only.</b> Unlike a real card this offers no isolation whatsoever: the
 * uploaded {@link OpenPGPKey.OpenPGPSecretKey secret keys} are held in the heap of the calling process
 * and {@link #getSoftwareKey} hands the private key straight back. It exists so that the smart-card API
 * can be exercised without hardware; never use it as a substitute for a token in production.
 */
public class SimulatorOpenPGPSmartCard
        extends OpenPGPSmartCard
{
    private final Integer serialNumber;

    private final Map<Byte, OpenPGPKey.OpenPGPSecretKey> secretKeys = new HashMap<>();

    public SimulatorOpenPGPSmartCard(SimulatorOpenPGPSmartCardBackend backend,
                                     Integer serialNumber)
    {
        super(backend);
        this.serialNumber = serialNumber;
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorOpenPGPSmartCardBackend backend,
                                                                    OpenPGPKey softwareKey)
            throws PGPException
    {
        // the serial only has to be unique among simulated cards; it is not security relevant, but
        // take it from the registrar's RNG rather than introducing a java.util.Random into the tree.
        return createSimulatedCardFrom(backend,
                Integers.valueOf(CryptoServicesRegistrar.getSecureRandom().nextInt()), softwareKey);
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorOpenPGPSmartCardBackend backend,
                                                                    Integer serialNumber,
                                                                    OpenPGPKey softwareKey)
            throws PGPException
    {
        SimulatorOpenPGPSmartCard card = new SimulatorOpenPGPSmartCard(backend, serialNumber);

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = softwareKey.getSigningKeys();
        if (!signingKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(signingKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE, secretKey.unlock(), null);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> decryptionKeys = softwareKey.getEncryptionKeys();
        if (!decryptionKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(decryptionKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION, secretKey.unlock(), null);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> authenticationKeys = softwareKey.getComponentKeysWithFlag(new Date(), KeyFlags.AUTHENTICATION);
        if (!authenticationKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(authenticationKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION, secretKey.unlock(), null);
        }

        return card;
    }

    private static OpenPGPHardwareKey asHardwareKey(OpenPGPSmartCard card,
                                                    OpenPGPKey.OpenPGPSecretKey key,
                                                    byte keyRef,
                                                    byte state)
    {
        return new OpenPGPHardwareKey(
                card,
                keyRef,
                state,
                key.getPGPPublicKey().getFingerprint(),
                key.getPGPPublicKey().getCreationTime());
    }

    @Override
    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    @Override
    public String getVersion()
    {
        return "1.0";
    }

    @Override
    public boolean isKeySupported(byte keyRef, OpenPGPCertificate.OpenPGPComponentKey key)
    {
        return true;
    }

    @Override
    public boolean isCurveSupported(byte keyRef, ASN1ObjectIdentifier curveOID) throws CardException {
        return true;
    }

    @Override
    public SimulatorOpenPGPSmartCard reset()
    {
        keys.clear();
        secretKeys.clear();
        return this;
    }

    /**
     * {@inheritDoc}
     * <p>
     * The simulator enforces no admin PIN, so <code>adminPin</code> is ignored.
     */
    @Override
    public SimulatorOpenPGPSmartCard uploadKey(byte keyRef,
                                               OpenPGPKey.OpenPGPPrivateKey key,
                                               char[] adminPin)
    {
        secretKeys.put(keyRef, key.getSecretKey());
        keys.put(keyRef, asHardwareKey(this, key.getSecretKey(), keyRef, OpenPGPHardwareKey.STATE_IMPORTED));
        return this;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns null if the given slot is empty, matching the hardware implementations.
     */
    @Override
    public PGPPublicKey reconstructPGPPublicKey(byte keyRef)
    {
        OpenPGPKey.OpenPGPSecretKey secretKey = secretKeys.get(keyRef);
        if (secretKey == null)
        {
            return null;
        }
        return secretKey.getPublicKey().getPGPPublicKey();
    }

    public PGPPrivateKey getSoftwareKey(OpenPGPCertificate.OpenPGPComponentKey key,
                                        KeyPassphraseProvider passphraseProvider)
            throws PGPException
    {
        for (Iterator<OpenPGPKey.OpenPGPSecretKey> it = secretKeys.values().iterator(); it.hasNext();)
        {
            OpenPGPKey.OpenPGPSecretKey k = it.next();
            if (k.getKeyIdentifier().matchesExplicit(key.getKeyIdentifier()))
            {
                return k.unlock(passphraseProvider).getKeyPair().getPrivateKey();
            }
        }
        return null;
    }

    @Override
    public String getCardType()
    {
        return "SimulatorSmartCard";
    }

    @Override
    public byte[] sign(byte[] data,
                       OpenPGPHardwareKey key,
                       OpenPGPKey.OpenPGPSecretKey stubKey,
                       KeyPassphraseProvider userPinProvider)
    {
        try
        {
            PGPPrivateKey pgpPrivateKey = getSoftwareKey(stubKey, userPinProvider);
            BcPGPKeyConverter converter = new BcPGPKeyConverter();
            AsymmetricKeyParameter privateKey = converter.getPrivateKey(pgpPrivateKey);

            switch (stubKey.getAlgorithm())
            {
                case PublicKeyAlgorithmTags.RSA_GENERAL:
                case PublicKeyAlgorithmTags.RSA_SIGN:
                    AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
                    rsaEngine.init(true, privateKey);
                    return rsaEngine.processBlock(data, 0, data.length);

                case PublicKeyAlgorithmTags.DSA:
                    DSASigner dsaEngine = new DSASigner();
                    dsaEngine.init(true, privateKey);
                    BigInteger[] dsaSig = dsaEngine.generateSignature(data);
                    return StandardDSAEncoding.INSTANCE.encode(dsaEngine.getOrder(), dsaSig[0], dsaSig[1]);

                case PublicKeyAlgorithmTags.ECDSA:
                    ECDSASigner ecdsaSigner = new ECDSASigner();
                    ecdsaSigner.init(true, privateKey);
                    BigInteger[] ecdsaSig = ecdsaSigner.generateSignature(data);
                    return StandardDSAEncoding.INSTANCE.encode(ecdsaSigner.getOrder(), ecdsaSig[0], ecdsaSig[1]);

                case PublicKeyAlgorithmTags.EDDSA_LEGACY:
                case PublicKeyAlgorithmTags.Ed25519:
                case PublicKeyAlgorithmTags.Ed448:
                    Signer edSigner;
                    if (stubKey.getAlgorithm() == PublicKeyAlgorithmTags.Ed25519 ||
                            (stubKey.getAlgorithm() == PublicKeyAlgorithmTags.EDDSA_LEGACY && privateKey instanceof Ed25519PrivateKeyParameters))
                    {
                        edSigner = new Ed25519Signer();
                    }
                    else
                    {
                        edSigner = new Ed448Signer(new byte[0]);
                    }
                    edSigner.init(true, privateKey);
                    edSigner.update(data, 0, data.length);
                    return edSigner.generateSignature();

                default:
                    throw new PGPException("Unknown public key algorithm: " + stubKey.getAlgorithm());
            }
        }
        catch (PGPException | IOException | CryptoException e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message, OpenPGPHardwareKey openPGPHardwareKey, OpenPGPKey.OpenPGPSecretKey stubKey, KeyPassphraseProvider userPinProvider) {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(PublicKey publicKey, OpenPGPHardwareKey openPGPHardwareKey, OpenPGPKey.OpenPGPSecretKey stubKey, KeyPassphraseProvider userPinProvider) {
        return new byte[0];
    }

}
