package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OpenPGPMessageProcessor
{
    public static int MAX_RECURSION = 16;

    // Source of certificates for signature verification
    private final OpenPGPCertificateSource certificateSource;
    // Source of decryption keys
    private final OpenPGPKeySource keySource;
    private final KeyPasswordCallback keyPasswordCallback;
    private final MessagePassphraseCallback messagePassphraseCallback;

    private final PGPSessionKey sessionKey;
    private final char[] messagePassphrase;

    private final PGPObjectFactoryProvider objectFactoryProvider;
    private final DataDecryptorFactoryBuilderProvider decryptorFactoryProvider;

    public OpenPGPMessageProcessor(OpenPGPCertificateSource certificateSource,
                                   OpenPGPKeySource keySource,
                                   KeyPasswordCallback keyPasswordCallback,
                                   MessagePassphraseCallback messagePassphraseCallback,
                                   PGPSessionKey sessionKey,
                                   char[] messagePassphrase,
                                   PGPObjectFactoryProvider objectFactoryProvider,
                                   DataDecryptorFactoryBuilderProvider decryptorFactoryProvider)
    {
        this.certificateSource = certificateSource;
        this.keySource = keySource;
        this.keyPasswordCallback = keyPasswordCallback;
        this.messagePassphraseCallback = messagePassphraseCallback;
        this.sessionKey = sessionKey;
        this.messagePassphrase = messagePassphrase;
        this.objectFactoryProvider = objectFactoryProvider;
        this.decryptorFactoryProvider = decryptorFactoryProvider;
    }

    public InputStream process(InputStream messageIn)
            throws IOException, PGPException
    {
        InputStream packetInputStream = PGPUtil.getDecoderStream(messageIn);
        int depth = 0;
        do
        {
            PGPObjectFactory objectFactory = objectFactoryProvider.provideFactory(packetInputStream);
            Object o = objectFactory.nextObject();

            // TODO: This is a brittle prototype implementation. Implement properly!

            if (o instanceof PGPEncryptedDataList)
            {
                PGPEncryptedDataList encDataList = (PGPEncryptedDataList) o;
                packetInputStream = decrypt(encDataList);
            }
            else if (o instanceof PGPCompressedData)
            {
                PGPCompressedData compData = (PGPCompressedData) o;
                packetInputStream = compData.getInputStream();
            }
            else if (o instanceof PGPLiteralData)
            {
                PGPLiteralData litData = (PGPLiteralData) o;
                // finally return the literal data
                return litData.getDataStream();
            }
        }
        while (++depth < MAX_RECURSION);

        throw new PGPException("Exceeded maximum packet layer depth.");
    }

    private InputStream decrypt(PGPEncryptedDataList encDataList)
            throws PGPException
    {
        // Since decryption using session key is the most "deliberate" and "specific", we'll try that first
        if (sessionKey != null)
        {
            SessionKeyDataDecryptorFactory decryptorFactory = decryptorFactoryProvider.build(sessionKey);
            InputStream decryptedIn = encDataList.extractSessionKeyEncryptedData()
                    .getDataStream(decryptorFactory);
            return decryptedIn;
        }

        List<PGPPBEEncryptedData> skesks = skesks(encDataList);
        List<PGPPublicKeyEncryptedData> pkesks = pkesks(encDataList);

        // If the user explicitly provided a message passphrase, we'll try that next
        if (messagePassphrase != null && !skesks.isEmpty())
        {
            PGPException exception = null;
            for (PGPPBEEncryptedData skesk : skesks)
            {
                try
                {
                    PBEDataDecryptorFactory decryptorFactory = decryptorFactoryProvider.build(messagePassphrase);
                    InputStream decryptedIn = skesk.getDataStream(decryptorFactory);
                    return decryptedIn;
                }
                catch (PGPException e)
                {
                    // cache first exception, then continue to try next skesk if present
                    exception = exception != null ? exception : e;
                }
            }
            throw exception;
        }

        // Then we'll try decryption using secret key(s)
        for (PGPPublicKeyEncryptedData pkesk : pkesks)
        {
            KeyIdentifier identifier = pkesk.getKeyIdentifier();
            OpenPGPKey key = keySource.provideKey(identifier);
            if (key == null)
            {
                continue;
            }

            OpenPGPKey.OpenPGPSecretKey decryptionKey = key.getSecretKeys().get(identifier);
            if (decryptionKey == null)
            {
                throw new PGPException("Certificate " + key.getKeyIdentifier() + " is missing the secret key component " + identifier);
            }

            if (!decryptionKey.isEncryptionKey())
            {
                throw new PGPException("Key is not an encryption key and can therefore not decrypt.");
            }

            char[] keyPassphrase = decryptionKey.isLocked() ? keyPasswordCallback.getKeyPassword(identifier) : null;
            PGPPrivateKey privateKey = decryptionKey.unlock(keyPassphrase);

            PublicKeyDataDecryptorFactory decryptorFactory = decryptorFactoryProvider.build(privateKey);
            InputStream decryptedIn = pkesk.getDataStream(decryptorFactory);
            return decryptedIn;
        }

        // And lastly, we'll prompt the user dynamically for a message passphrase
        if (!skesks.isEmpty() && messagePassphraseCallback != null)
        {
            char[] passphrase;
            PGPException exception = null;

            while ((passphrase = messagePassphraseCallback.getMessagePassphrase()) != null)
            {
                for (PGPPBEEncryptedData skesk : skesks)
                {
                    try
                    {
                        PBEDataDecryptorFactory decryptorFactory = decryptorFactoryProvider.build(passphrase);
                        InputStream decryptedIn = skesk.getDataStream(decryptorFactory);
                        return decryptedIn;
                    }
                    catch (PGPException e)
                    {
                        // cache first exception, then continue to try next skesk if present
                        exception = exception != null ? exception : e;
                    }
                }
            }

            if (exception != null)
            {
                throw exception;
            }
        }

        throw new PGPException("No working decryption method found.");
    }

    private List<PGPPBEEncryptedData> skesks(PGPEncryptedDataList encDataList)
    {
        List<PGPPBEEncryptedData> list = new ArrayList<>();
        for (PGPEncryptedData encData : encDataList)
        {
            if (encData instanceof PGPPBEEncryptedData)
            {
                list.add((PGPPBEEncryptedData) encData);
            }
        }
        return list;
    }

    private List<PGPPublicKeyEncryptedData> pkesks(PGPEncryptedDataList encDataList)
    {
        List<PGPPublicKeyEncryptedData> list = new ArrayList<>();
        for (PGPEncryptedData encData : encDataList)
        {
            if (encData instanceof PGPPublicKeyEncryptedData)
            {
                list.add((PGPPublicKeyEncryptedData) encData);
            }
        }
        return list;
    }

    /**
     * Implementation of {@link OpenPGPCertificateSource} which sources {@link OpenPGPCertificate certificates}
     * from a {@link Map} and - in case of a miss - optionally invokes another instance of
     * {@link OpenPGPCertificateSource} as a dynamic callback.
     */
    public static class OpenPGPCertificatePool
            implements OpenPGPCertificateSource
    {
        private final Map<KeyIdentifier, OpenPGPCertificate> pool = new HashMap<>();
        private OpenPGPCertificateSource missingCertCallback = null;
        private boolean cacheCertificatesFromCallback = true;

        public OpenPGPCertificatePool()
        {

        }

        public OpenPGPCertificatePool(List<OpenPGPCertificate> certificates)
        {
            for (OpenPGPCertificate certificate : certificates)
            {
                addCertificate(certificate);
            }
        }

        /**
         * Set a callback that gets fired whenever a certificate is requested, which is not found in the pool.
         *
         * @param callback callback
         * @return this
         */
        public OpenPGPCertificatePool setMissingCertificateCallback(OpenPGPCertificateSource callback)
        {
            this.missingCertCallback = callback;
            return this;
        }

        /**
         * Decide, whether the implementation should add {@link OpenPGPCertificate certificates} returned by
         * {@link #missingCertCallback} to the pool of cached certificates.
         *
         * @param cacheCertificatesFromCallback if true, cache certificates from callback
         * @return this
         */
        public OpenPGPCertificatePool setCacheCertificatesFromCallback(boolean cacheCertificatesFromCallback)
        {
            this.cacheCertificatesFromCallback = cacheCertificatesFromCallback;
            return this;
        }

        @Override
        public OpenPGPCertificate provideCertificate(KeyIdentifier subkeyIdentifier)
        {
            OpenPGPCertificate certificate = pool.get(subkeyIdentifier);
            if (certificate == null && missingCertCallback != null)
            {
                certificate = missingCertCallback.provideCertificate(subkeyIdentifier);
                if (cacheCertificatesFromCallback && certificate != null)
                {
                    addCertificate(certificate);
                }
            }
            return certificate;
        }

        /**
         * Add a certificate to the pool.
         *
         * @param certificate certificate
         * @return this
         */
        public OpenPGPCertificatePool addCertificate(OpenPGPCertificate certificate)
        {
            if (certificate != null)
            {
                for (KeyIdentifier identifier : certificate.getAllKeyIdentifiers())
                {
                    pool.put(identifier, certificate);
                }
            }
            return this;
        }
    }

    /**
     * Interface for requesting {@link OpenPGPCertificate OpenPGPCertificates} by providing a {@link KeyIdentifier}.
     * The {@link KeyIdentifier} can either be that of the certificates primary key, or of a subkey.
     */
    public interface OpenPGPCertificateSource
    {
        /**
         * Return the requested {@link OpenPGPCertificate}.
         * The passed {@link KeyIdentifier} is that of either the primary key or of a subkey of the certificate.
         * Returning null means, that the requested certificate cannot be provided.
         *
         * @param subkeyIdentifier identifier
         * @return certificate or null
         */
        OpenPGPCertificate provideCertificate(KeyIdentifier subkeyIdentifier);
    }

    /**
     * Interface for requesting {@link OpenPGPKey OpenPGPKeys} by providing a {@link KeyIdentifier}.
     * The {@link KeyIdentifier} can either be that of the keys primary key, or of a subkey.
     */
    public interface OpenPGPKeySource
    {
        /**
         * Return the requested {@link OpenPGPKey}.
         * Returning null means, that the requested key cannot be provided.
         *
         * @param subkeyIdentifier identifier
         * @return key or null
         */
        OpenPGPKey provideKey(KeyIdentifier subkeyIdentifier);
    }

    public interface KeyPasswordCallback
    {
        /**
         * Return the passphrase for the given key.
         * This callback is only fired, if the key is locked and a passphrase is required to unlock it.
         * Returning null means, that the passphrase is not available.
         *
         * @param keyIdentifier identifier of the locked (sub-)key.
         * @return passphrase or null
         */
        char[] getKeyPassword(KeyIdentifier keyIdentifier);
    }

    /**
     * Callback for requesting message passphrases at runtime.
     */
    public interface MessagePassphraseCallback
    {
        /**
         * Return a passphrase for decrypting a symmetrically encrypted message.
         * This callback is only fired, if one or more Symmetric-Key-Encrypted-Session-Key (SKESK) packets are
         * encountered.
         * Returning null means, that no passphrase can be provided.
         * @return message password
         */
        char[] getMessagePassphrase();
    }

    public static class Result
    {
        private final OpenPGPKey decryptionKey;
        private final PGPSessionKey sessionKey;
        private final List<OpenPGPSignature.OpenPGPDataSignature> signatures;

        private Result(OpenPGPKey decryptionKey,
                       PGPSessionKey sessionKey,
                       List<OpenPGPSignature.OpenPGPDataSignature> signatures)
        {
            this.decryptionKey = decryptionKey;
            this.sessionKey = sessionKey;
            this.signatures = signatures;
        }

        public OpenPGPKey getDecryptionKey()
        {
            return decryptionKey;
        }

        public PGPSessionKey getSessionKey()
        {
            return sessionKey;
        }

        public List<OpenPGPSignature.OpenPGPDataSignature> getSignatures()
        {
            return new ArrayList<>(signatures);
        }
    }

    public interface PGPObjectFactoryProvider
    {
        PGPObjectFactory provideFactory(InputStream inputStream);
    }

    public interface DataDecryptorFactoryBuilderProvider
    {
        SessionKeyDataDecryptorFactory build(PGPSessionKey sessionKey);

        PublicKeyDataDecryptorFactory build(PGPPrivateKey privateKey);

        PBEDataDecryptorFactory build(char[] passphrase);
    }

    public static class BcDataDecryptorFactoryBuilderProvider
            implements DataDecryptorFactoryBuilderProvider
    {
        private final BcPGPDigestCalculatorProvider digestCalculatorProvider;

        public BcDataDecryptorFactoryBuilderProvider(BcPGPDigestCalculatorProvider digestCalculatorProvider)
        {
            this.digestCalculatorProvider = digestCalculatorProvider;
        }

        @Override
        public SessionKeyDataDecryptorFactory build(PGPSessionKey sessionKey)
        {
            return new BcSessionKeyDataDecryptorFactory(sessionKey);
        }

        @Override
        public PublicKeyDataDecryptorFactory build(PGPPrivateKey privateKey)
        {
            return new BcPublicKeyDataDecryptorFactory(privateKey);
        }

        @Override
        public PBEDataDecryptorFactory build(char[] passphrase)
        {
            return new BcPBEDataDecryptorFactory(passphrase, digestCalculatorProvider);
        }
    }

    public static class JcaDataDecryptorFactoryBuilderProvider
            implements DataDecryptorFactoryBuilderProvider
    {

        private final Provider provider;
        private final PGPDigestCalculatorProvider digestCalculatorProvider;

        public JcaDataDecryptorFactoryBuilderProvider(Provider provider,
                                                      PGPDigestCalculatorProvider digestCalculatorProvider)
        {
            this.provider = provider;
            this.digestCalculatorProvider = digestCalculatorProvider;
        }

        @Override
        public SessionKeyDataDecryptorFactory build(PGPSessionKey sessionKey) {
            return new JceSessionKeyDataDecryptorFactoryBuilder()
                    .setProvider(provider)
                    .build(sessionKey);
        }

        @Override
        public PublicKeyDataDecryptorFactory build(PGPPrivateKey privateKey) {
            return new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider(provider)
                    .build(privateKey);
        }

        @Override
        public PBEDataDecryptorFactory build(char[] passphrase) {
            return new JcePBEDataDecryptorFactoryBuilder(digestCalculatorProvider)
                    .setProvider(provider)
                    .build(passphrase);
        }
    }
}
