package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPException;

/**
 * Callback isolating the raw public-key operations performed while recovering an OpenPGP session key.
 * <p>
 * {@link BcPublicKeyDataDecryptorFactory} performs all packet parsing, length checking and KDF/key-unwrap
 * work itself and delegates only the private-key operation - an RSA or ElGamal decryption, or an
 * ECDH / X25519 / X448 agreement - to an instance of this class. A subclass may therefore route that one
 * operation to a hardware device (a smart card or HSM) without reimplementing any of the session-key
 * recovery logic. See {@code org.bouncycastle.openpgp.operator.bc.BcExternalPublicKeyDataDecryptorFactory}
 * for the externally-backed-key base class built on this seam.
 * <p>
 * This is the lightweight (<code>.bc</code>) binding: keys are passed as
 * {@link AsymmetricKeyParameter}. It deliberately lives in the <code>.bc</code> subpackage rather than
 * alongside {@link org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory}, because the
 * top-level <code>operator</code> package is JCA-free <em>and</em> lightweight-crypto-free.
 */
public abstract class BcPublicKeyCryptoCallback
{
    public abstract byte[] decrypt(int keyAlgorithm,
                                   byte[][] pEnc)
        throws PGPException, InvalidCipherTextException;

    public abstract byte[] decrypt(int keyAlgorithm,
                                   AsymmetricKeyParameter peerKey)
        throws PGPException, InvalidCipherTextException;
}
