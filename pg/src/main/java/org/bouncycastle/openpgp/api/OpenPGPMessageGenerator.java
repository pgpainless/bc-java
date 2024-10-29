package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class OpenPGPMessageGenerator
{
    public static final int BUFFER_SIZE = 1024;

    private Configuration config = new Configuration();

    // Factory for creating ASCII armor
    private ArmoredOutputStreamFactory armorStreamFactory =
            outputStream -> ArmoredOutputStream.builder()
                    .clearHeaders()                   // Hide version
                    .enableCRC(false)   // Disable CRC sum
                    .build(outputStream);

    // TODO: Implement properly
    private EncryptionNegotiator encryptionNegotiator =
            configuration ->
            {
                if (configuration.recipients.isEmpty() && configuration.passphrases.isEmpty())
                {
                    return MessageEncryption.unencrypted();
                }
                else
                {
                    return MessageEncryption.aead(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
                }
            };

    // TODO: Implement properly, taking encryption into account (sign-only should not compress)
    private CompressionNegotiator compressionNegotiator =
            configuration -> CompressionAlgorithmTags.UNCOMPRESSED;

    // TODO: Implement properly
    private SubkeySelector encryptionKeySelector =
            keyRing -> Collections.singletonList(KeyIdentifier.wildcard());

    // TODO: Implement properly
    private SubkeySelector signingKeySelector =
            keyRing -> Collections.singletonList(KeyIdentifier.wildcard());

    // Literal Data metadata
    private Date fileModificationDate = null;
    private String filename = null;
    private char format = PGPLiteralData.BINARY;

    /**
     * Replace the {@link ArmoredOutputStreamFactory} with a custom implementation.
     *
     * @param factory factory for {@link ArmoredOutputStream} instances
     * @return this
     */
    public OpenPGPMessageGenerator setArmorStreamFactory(ArmoredOutputStreamFactory factory)
    {
        this.armorStreamFactory = factory;
        return this;
    }

    /**
     * Replace the default encryption key selector with a custom implementation.
     * The encryption key selector is responsible for selecting one or more encryption subkeys from a
     * recipient certificate.
     *
     * @param encryptionKeySelector selector for encryption (sub-)keys
     * @return this
     */
    public OpenPGPMessageGenerator setEncryptionKeySelector(SubkeySelector encryptionKeySelector)
    {
        this.encryptionKeySelector = encryptionKeySelector;
        return this;
    }

    /**
     * Replace the default {@link EncryptionNegotiator} with a custom implementation.
     * The {@link EncryptionNegotiator} is used to negotiate, how to encrypt the message, given all recipient
     * keys and passphrases.
     *
     * @param encryptionNegotiator negotiator
     * @return this
     */
    public OpenPGPMessageGenerator setEncryptionNegotiator(EncryptionNegotiator encryptionNegotiator)
    {
        this.encryptionNegotiator = encryptionNegotiator;
        return this;
    }

    /**
     * Replace the default {@link CompressionNegotiator} with a custom implementation.
     * The {@link CompressionNegotiator} is used to negotiate, whether and how to compress the literal data packet.
     *
     * @param compressionNegotiator negotiator
     * @return this
     */
    public OpenPGPMessageGenerator setCompressionNegotiator(CompressionNegotiator compressionNegotiator)
    {
        this.compressionNegotiator = compressionNegotiator;
        return this;
    }

    /**
     * Replace the default signing key selector with a custom implementation.
     * The signing key selector is responsible for selecting one or more signing subkeys from a signing key.
     *
     * @param signingKeySelector selector for signing (sub-)keys
     * @return this
     */
    public OpenPGPMessageGenerator setSigningKeySelector(SubkeySelector signingKeySelector)
    {
        this.signingKeySelector = signingKeySelector;
        return this;
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the default {@link #encryptionKeySelector}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     */
    public void addEncryptionCertificate(PGPPublicKeyRing recipientCertificate)
    {
        addEncryptionCertificate(recipientCertificate, encryptionKeySelector);
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the provided {@link SubkeySelector}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     * @param subkeySelector selector for encryption subkeys
     */
    public void addEncryptionCertificate(PGPPublicKeyRing recipientCertificate, SubkeySelector subkeySelector)
    {
        config.recipients.add(new Recipient(recipientCertificate, subkeySelector));
    }

    /**
     * Add a message passphrase.
     * In addition to optional public key encryption, the message will be decryptable using the given passphrase.
     *
     * @param passphrase passphrase
     */
    public void addEncryptionPassphrase(char[] passphrase)
    {
        config.passphrases.add(passphrase);
    }

    /**
     * Sign the message using a secret signing key.
     *
     * @param signingKey OpenPGP key
     * @param signingKeyDecryptor decryptor to unlock the signing (sub-)keys.
     */
    public void addSigningKey(PGPSecretKeyRing signingKey, PBESecretKeyDecryptor signingKeyDecryptor)
    {
        addSigningKey(signingKey, signingKeyDecryptor, signingKeySelector);
    }

    /**
     * Sign the message using a secret signing key.
     *
     * @param signingKey OpenPGP key
     * @param signingKeyDecryptor decryptor to unlock the signing (sub-)keys.
     * @param subkeySelector selector for selecting signing subkey(s)
     */
    public void addSigningKey(PGPSecretKeyRing signingKey, PBESecretKeyDecryptor signingKeyDecryptor, SubkeySelector subkeySelector)
    {
        config.signingKeys.add(new Signer(signingKey, signingKeyDecryptor, subkeySelector));
    }

    /**
     * Specify, whether the output OpenPGP message will be ASCII armored or not.
     *
     * @param armored boolean
     * @return this
     */
    public OpenPGPMessageGenerator setArmored(boolean armored)
    {
        this.config.setArmored(armored);
        return this;
    }

    public OpenPGPMessageGenerator setFileMetadata(File file)
    {
        this.filename = file.getName();
        this.fileModificationDate = new Date(file.lastModified());
        return this;
    }

    /**
     * Open an {@link OpenPGPMessageOutputStream} over the given output stream.
     * @param out output stream
     * @return OpenPGP message output stream
     * @throws PGPException if the output stream cannot be created
     */
    public OutputStream open(OutputStream out)
            throws PGPException
    {
        OpenPGPMessageOutputStream pgpOut = new OpenPGPMessageOutputStream(out);
        applyOptionalAsciiArmor(pgpOut);
        applyPacketEncoding(pgpOut);
        applyOptionalEncryption(pgpOut);
        applySignatures(pgpOut);
        applyOptionalCompression(pgpOut);
        applyLiteralDataWrap(pgpOut);
        return pgpOut;
    }

    /**
     * Apply ASCII armor if necessary.
     * The output will only be wrapped in ASCII armor, if {@link #setArmored(boolean)} is set
     * to true (is true by default).
     * The {@link ArmoredOutputStream} will be instantiated using the {@link ArmoredOutputStreamFactory}
     * which can be replaced using {@link #setArmorStreamFactory(ArmoredOutputStreamFactory)}.
     *
     * @param out OpenPGP message output stream
     * @throws PGPException if ASCII armor cannot be added
     */
    private void applyOptionalAsciiArmor(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        if (config.isArmored)
        {
            out.addLayer(armorStreamFactory);
        }
    }

    /**
     * Apply OpenPGP packet encoding using a {@link BCPGOutputStream}.
     *
     * @param out OpenPGP message output stream
     * @throws PGPException if packet encoding cannot be applied
     */
    private void applyPacketEncoding(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        out.addLayer(o -> new BCPGOutputStream(o, PacketFormat.CURRENT));
    }

    /**
     * Optionally apply message encryption.
     * If no recipient certificates and no encryption passphrases were supplied, no encryption
     * will be applied.
     * Otherwise, encryption mode and algorithms will be negotiated and message encryption will be applied.
     *
     * @param out OpenPGP message output stream
     * @throws PGPException if message encryption cannot be applied
     */
    private void applyOptionalEncryption(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        MessageEncryption encryption = encryptionNegotiator.negotiateEncryption(config);
        if (!encryption.isEncrypted())
        {
            return; // No encryption
        }

        PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(encryption.symmetricKeyAlgorithm);

        // Specify container type for the plaintext
        switch (encryption.mode)
        {
            case SEIPDv1:
                encBuilder.setWithIntegrityPacket(true);
                break;

            case SEIPDv2:
                encBuilder.setWithAEAD(encryption.aeadAlgorithm, 6);
                encBuilder.setUseV6AEAD();
                break;

            case LIBREPGP_OED:
                encBuilder.setWithAEAD(encryption.aeadAlgorithm, 6);
                encBuilder.setUseV5AEAD();
                break;
        }

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
        // For sake of interoperability and simplicity, we always use a dedicated session key for message encryption
        //  even if only a single PBE encryption method was added and S2K result could be used as session-key directly.
        encGen.setForceSessionKey(true);

        // Setup asymmetric message encryption
        for (Recipient recipient : config.recipients)
        {
            for (PGPPublicKey encryptionSubkey : recipient.encryptionKeys())
            {
                encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encryptionSubkey));
            }
        }

        // Setup symmetric (password-based) message encryption
        for (char[] passphrase : config.passphrases)
        {
            PBEKeyEncryptionMethodGenerator skeskGen;
            switch (encryption.mode)
            {
                case SEIPDv1:
                case LIBREPGP_OED:
                    // "v4" and LibrePGP use symmetric-key encrypted session key packets version 4 (SKESKv4)
                    skeskGen = new BcPBEKeyEncryptionMethodGenerator(passphrase);
                    break;

                case SEIPDv2:
                    // v6 uses symmetric-key encrypted session key packets version 6 (SKESKv6) using AEAD
                    skeskGen = new BcPBEKeyEncryptionMethodGenerator(passphrase, S2K.Argon2Params.memoryConstrainedParameters());
                    break;
                default: continue;
            }

            skeskGen.setSecureRandom(CryptoServicesRegistrar.getSecureRandom()); // Prevent NPE
            encGen.addMethod(skeskGen);
        }

        // Finally apply encryption
        out.addLayer(o ->
        {
            try
            {
                return encGen.open(o, new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not open encryptor OutputStream", e);
            }
        });
    }

    /**
     * Apply OpenPGP inline-signatures.
     * @param out OpenPGP message output stream
     * @throws PGPException if signatures cannot be generated
     */
    private void applySignatures(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        // TODO: Implement
    }

    private void applyOptionalCompression(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        int compressionAlgorithm = compressionNegotiator.negotiateCompression(config);
        if (compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED)
        {
            return; // Uncompressed
        }

        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(compressionAlgorithm);

        out.addLayer(o ->
        {
            try
            {
                return compGen.open(o, new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not apply compression", e);
            }
        });
    }

    /**
     * Setup wrapping of the message plaintext in a literal data packet.
     *
     * @param out OpenPGP message output stream
     * @throws PGPException if literal data wrapping cannot be applied
     */
    private void applyLiteralDataWrap(OpenPGPMessageOutputStream out)
            throws PGPException
    {
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        out.addLayer(o ->
        {
            try
            {
                return litGen.open(o,
                        format,
                        filename != null ? filename : "",
                        fileModificationDate != null ? fileModificationDate : PGPLiteralData.NOW,
                        new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not apply literal data wrapping", e);
            }
        });
    }

    public interface ArmoredOutputStreamFactory
            extends OpenPGPMessageOutputStream.OutputStreamFactory
    {
        ArmoredOutputStream get(OutputStream out);
    }

    public interface CompressionNegotiator
    {
        /**
         * Negotiate a compression algorithm.
         * Returning {@link org.bouncycastle.bcpg.CompressionAlgorithmTags#UNCOMPRESSED} will result in no compression.
         *
         * @param configuration message generator configuration
         * @return negotiated compression algorithm ID
         */
        int negotiateCompression(Configuration configuration);
    }

    public interface EncryptionNegotiator
    {
        /**
         * Negotiate encryption mode and algorithms.
         *
         * @param configuration message generator configuration
         * @return negotiated encryption mode and algorithms
         */
        MessageEncryption negotiateEncryption(Configuration configuration);
    }

    public static class Configuration
    {
        private Date creationDate = new Date();
        private boolean isArmored = true;
        private final List<Recipient> recipients = new ArrayList<>();
        private final List<Signer> signingKeys = new ArrayList<>();
        private final List<char[]> passphrases = new ArrayList<>();

        public Configuration setArmored(boolean isArmored)
        {
            this.isArmored = isArmored;
            return this;
        }

        public Configuration setCreationDate(Date messageCreation)
        {
            this.creationDate = messageCreation;
            return this;
        }
    }

    /**
     * Tuple representing a recipients OpenPGP certificate.
     */
    static class Recipient
    {
        private final PGPPublicKeyRing certificate;
        private final SubkeySelector subkeySelector;

        /**
         * Create a {@link Recipient}.
         *
         * @param certificate OpenPGP certificate (public key)
         * @param subkeySelector selector to select encryption-capable subkeys from the certificate
         */
        public Recipient(PGPPublicKeyRing certificate, SubkeySelector subkeySelector)
        {
            this.certificate = certificate;
            this.subkeySelector = subkeySelector;
        }

        /**
         * Return a set of {@link PGPPublicKey subkeys} which will be used for message encryption.
         *
         * @return encryption capable subkeys for this recipient
         */
        public List<PGPPublicKey> encryptionKeys()
        {
            // we first construct a set, so that we don't accidentally encrypt the message multiple times for the
            //  same subkey (e.g. if wildcards KeyIdentifiers are used).
            Set<PGPPublicKey> encryptionKeys = new LinkedHashSet<>();
            for (KeyIdentifier identifier : subkeySelector.select(certificate))
            {
                Iterator<PGPPublicKey> selected = certificate.getPublicKeys(identifier);
                while (selected.hasNext())
                {
                    encryptionKeys.add(selected.next());
                }
            }
            return new ArrayList<>(encryptionKeys);
        }
    }

    /**
     * Tuple representing an OpenPGP key used for signing.
     */
    static class Signer
    {
        private final PGPSecretKeyRing signingKey;
        private final PBESecretKeyDecryptor decryptor;
        private final SubkeySelector subkeySelector;

        /**
         * Create a {@link Signer}.
         * TODO: If there are multiple signing subkeys with different passphrases, we need multiple decryptors.
         *
         * @param signingKey OpenPGP key
         * @param decryptor decryptor to unlock the signing subkey
         * @param subkeySelector selector to select the signing subkey
         */
        public Signer(PGPSecretKeyRing signingKey, PBESecretKeyDecryptor decryptor, SubkeySelector subkeySelector)
        {
            this.signingKey = signingKey;
            this.decryptor = decryptor;
            this.subkeySelector = subkeySelector;
        }
    }

    /**
     * Encryption mode (SEIPDv1 / SEIPDv2 / OED) and algorithms.
     */
    public static class MessageEncryption
    {
        private final EncryptionMode mode;
        private final int symmetricKeyAlgorithm;
        private final int aeadAlgorithm;

        /**
         * Create a {@link MessageEncryption} tuple.
         *
         * @param mode encryption mode (packet type)
         * @param symmetricKeyAlgorithm symmetric key algorithm for message encryption
         * @param aeadAlgorithm aead algorithm for message encryption
         */
        private MessageEncryption(EncryptionMode mode, int symmetricKeyAlgorithm, int aeadAlgorithm)
        {
            this.mode = mode;
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            this.aeadAlgorithm = aeadAlgorithm;
        }

        /**
         * The data will not be encrypted.
         * Useful for sign-only operations.
         *
         * @return unencrypted encryption setup
         */
        public static MessageEncryption unencrypted()
        {
            return new MessageEncryption(EncryptionMode.SEIPDv1, SymmetricKeyAlgorithmTags.NULL, 0);
        }

        /**
         * The data will be encrypted and integrity protected using a SEIPDv1 packet.
         *
         * @param symmetricKeyAlgorithm symmetric cipher algorithm for message encryption
         * @return sym. enc. integrity protected encryption setup
         */
        public static MessageEncryption integrityProtected(int symmetricKeyAlgorithm)
        {
            return new MessageEncryption(EncryptionMode.SEIPDv1, symmetricKeyAlgorithm, 0);
        }

        /**
         * The data will be OCB-encrypted as specified by the non-standard LibrePGP document.
         *
         * @param symmetricKeyAlgorithm symmetric key algorithm which will be combined with OCB to form
         *                              an OCB-encrypted data packet
         * @return LibrePGP OCB encryption setup
         */
        public static MessageEncryption librePgp(int symmetricKeyAlgorithm)
        {
            return new MessageEncryption(EncryptionMode.LIBREPGP_OED, symmetricKeyAlgorithm, AEADAlgorithmTags.OCB);
        }

        /**
         * The data will be AEAD-encrypted using the method described in RFC9580.
         *
         * @param symmetricKeyAlgorithm symmetric cipher algorithm
         * @param aeadAlgorithm AEAD algorithm
         * @return AEAD encryption setup
         */
        public static MessageEncryption aead(int symmetricKeyAlgorithm, int aeadAlgorithm)
        {
            return new MessageEncryption(EncryptionMode.SEIPDv2, symmetricKeyAlgorithm, aeadAlgorithm);
        }

        /**
         * Return true, if the message will be encrypted.
         * @return is encrypted
         */
        public boolean isEncrypted()
        {
            return symmetricKeyAlgorithm != SymmetricKeyAlgorithmTags.NULL;
        }
    }

    /**
     * Encryption Mode.
     */
    public enum EncryptionMode
    {
        /**
         * Symmetrically-Encrypted-Integrity-Protected Data packet version 1.
         * This method protects the message using symmetric encryption as specified in RFC4880.
         * Support for this encryption mode is signalled using
         * {@link org.bouncycastle.bcpg.sig.Features#FEATURE_MODIFICATION_DETECTION}.
         */
        SEIPDv1, // v4

        /**
         * Symmetrically-Encrypted-Integrity-Protected Data packet version 2.
         * This method protects the message using an AEAD encryption scheme specified in RFC9580.
         * Support for this feature is signalled using {@link org.bouncycastle.bcpg.sig.Features#FEATURE_SEIPD_V2}.
         */
        SEIPDv2, // v6

        /**
         * LibrePGP OCB-Encrypted Data packet.
         * This method protects the message using an AEAD encryption scheme specified in LibrePGP.
         * Support for this feature is signalled using {@link org.bouncycastle.bcpg.sig.Features#FEATURE_AEAD_ENCRYPTED_DATA}.
         */
        LIBREPGP_OED // "v5"
    }

    /**
     * Interface for selecting a subset of keys from a {@link PGPKeyRing}.
     * This is useful e.g. for selecting a signing key from an OpenPGP key, or a for selecting all
     * encryption capable subkeys of a certificate.
     */
    public interface SubkeySelector
    {
        /**
         * Given a {@link PGPKeyRing}, select a subset of the key rings (sub-)keys and return their
         * {@link KeyIdentifier KeyIdentifiers}.
         *
         * @param keyRing OpenPGP key or certificate
         * @return non-null list of identifiers
         */
        List<KeyIdentifier> select(PGPKeyRing keyRing);
    }
}
