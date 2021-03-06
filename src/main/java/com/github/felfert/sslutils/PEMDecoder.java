package com.github.felfert.sslutils;

import java.io.ByteArrayInputStream;

import java.math.BigInteger;
import java.nio.charset.Charset;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.Collection;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A decoder, capable of decoding PEM-encoded keys and certificates.
 * @author <a href="mailto:gds2@fritz-elfert.de">Fritz Elfert</a>
 * @author <a href="mailto:plattner@trilead.com">Christian Plattner</a> (Original code fragments - BSD-licensed)
 */
public final class PEMDecoder {

    static final Logger LOGGER = LoggerFactory.getLogger(PEMDecoder.class);

    private static final Pattern PRIVKEY_DSA_BEGIN = Pattern.compile("^-----BEGIN DSA PRIVATE KEY-----\n");
    private static final Pattern PRIVKEY_DSA_END = Pattern.compile("\n-----END DSA PRIVATE KEY-----\\s*$");
    private static final Pattern PRIVKEY_RSA_BEGIN = Pattern.compile("^-----BEGIN RSA PRIVATE KEY-----\n");
    private static final Pattern PRIVKEY_RSA_END = Pattern.compile("\n-----END RSA PRIVATE KEY-----\\s*$");
    private static final Pattern PRIVKEY_EC_BEGIN = Pattern.compile("^-----BEGIN EC PRIVATE KEY-----\n");
    private static final Pattern PRIVKEY_EC_END = Pattern.compile("-----END EC PRIVATE KEY-----\\s*$");

    private static final Pattern PRIVKEY_PROCTYPE = Pattern.compile("^Proc-Type:\\s+4,ENCRYPTED\n");
    private static final Pattern PRIVKEY_DEKINFO = Pattern.compile("^DEK-Info:\\s+([^,]+),(\\S+)\n");

    private enum KeyType {
        UNKNOWN,
        RSA,
        DSA,
        EC
    }

    private enum KeyAlgo {
        UNKNOWN,
        AES_128_CBC,
        AES_192_CBC,
        AES_256_CBC,
        DES_EDE3_CBC,
        DES_CBC
    }

    /**
     * Decodes PEM-encoded certificates.
     *
     * @param pem The PEM encoded content to decode.
     * @return A list of Certificates.
     * @throws CertificateException if a certificate could not be decoded.
     */
    public Collection<? extends Certificate> decodeCertificates(final String pem) throws CertificateException {
        if (null == pem || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM data is null or empty");
        }
        try {
            final ByteArrayInputStream bis = new ByteArrayInputStream(pem.getBytes(Charset.defaultCharset()));
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificates(bis);
        } catch (Throwable t) {
            LOGGER.warn("", t);
            throw t;
        }
    }

    /**
     * Decodes a PEM-encoded private key.
     * If the key is encrypted, it is expected to be encoded
     * according to <a href="http://www.ietf.org/rfc/rfc1421.txt">RFC 1421</a>.<p>
     * This means, that it <b>MUST</b> contain a Proc-Type header as well as a
     * DEK-Info header, describing the algorithm used for encryption.</p>
     * The information, contained in the DEK-Info header <b>MUST</b> adhere to
     * <a href="http://www.ietf.org/rfc/rfc1423.txt">RFC 1423</a>.
     * @param pem The PEM encoded content to decode.
     * @param password The password to be used for description. (may be null, if the key is unencrypted).
     * @return A KeyPair, created from the decoded content.
     */
    public KeyPair decodePrivKey(final String pem, final String password) {
        boolean encrypted = false;
        KeyType keyType = KeyType.UNKNOWN;

        KeyAlgo algo = KeyAlgo.UNKNOWN;
        String tmp = null;
        byte []salt = null;
        if (null == pem) {
            throw new IllegalArgumentException("Not a PEM-encoded private key");
        }
        if (PRIVKEY_RSA_BEGIN.matcher(pem).find() && PRIVKEY_RSA_END.matcher(pem).find()) {
            tmp = PRIVKEY_RSA_BEGIN.matcher(pem).replaceFirst("");
            tmp = PRIVKEY_RSA_END.matcher(tmp).replaceFirst("").trim();
            keyType = KeyType.RSA;
        }
        if (PRIVKEY_DSA_BEGIN.matcher(pem).find() && PRIVKEY_DSA_END.matcher(pem).find()) {
            tmp = PRIVKEY_DSA_BEGIN.matcher(pem).replaceFirst("");
            tmp = PRIVKEY_DSA_END.matcher(tmp).replaceFirst("").trim();
            keyType = KeyType.DSA;
        }
        if (PRIVKEY_EC_BEGIN.matcher(pem).find() && PRIVKEY_EC_END.matcher(pem).find()) {
            tmp = PRIVKEY_EC_BEGIN.matcher(pem).replaceFirst("");
            tmp = PRIVKEY_EC_END.matcher(tmp).replaceFirst("").trim();
            keyType = KeyType.EC;
        }
        if (keyType.equals(KeyType.UNKNOWN)) {
            throw new IllegalArgumentException("Not a PEM-encoded private key");
        }

        if (PRIVKEY_PROCTYPE.matcher(tmp).find()) {
            encrypted = true;
            tmp = PRIVKEY_PROCTYPE.matcher(tmp).replaceFirst("").trim();
            final Matcher m = PRIVKEY_DEKINFO.matcher(tmp);
            if (m.find()) {
                try {
                    algo = KeyAlgo.valueOf(m.group(1).replaceAll("-", "_"));
                } catch (Throwable t) {
                    throw new IllegalArgumentException("Invalid or unsupported algorithm in DEK-Info", t);
                }
                final String saltstr = m.group(2);
                if (0 != saltstr.length() % 2 || saltstr.length() < 16) { // !MAGIC
                    throw new IllegalArgumentException("Length of hex salt in DEK-Info is less than 16 or not a multiple of 2");
                }
                salt = DatatypeConverter.parseHexBinary(saltstr.toUpperCase(Locale.getDefault()));
                tmp = PRIVKEY_DEKINFO.matcher(tmp).replaceFirst("").trim();
            } else {
                throw new IllegalArgumentException("Missing or invalid DEK-Info header");
            }
        }
        byte []data = DatatypeConverter.parseBase64Binary(tmp);

        if (encrypted) {
            if (null == password) {
                throw new IllegalArgumentException("PEM is encrypted, but no password was specified");
            }
            data = decryptPEM(data, algo, salt, password.getBytes(Charset.defaultCharset()));
        }
        return decodePrivKey(data, keyType);
    }

    /**
     * Decodes the DER-encoded key.
     * @param data The unencrypted binary key.
     * @param keyType The key type, fetched from the DEK-Info header.
     * @return A KeyPair, conatining a public/private key pair.
     */
    private KeyPair decodePrivKey(final byte []data, final KeyType keyType) {
        final SimpleDERReader dr = new SimpleDERReader(data);
        final byte[] seq = dr.readSequenceAsByteArray();
        if (dr.available() != 0) {
            throw new IllegalArgumentException("Padding in PRIVATE KEY DER stream.");
        }
        dr.resetInput(seq);
        final BigInteger version = dr.readInt();

        switch (keyType) {
            case DSA:
                if (version.compareTo(BigInteger.ZERO) != 0) {
                    throw new IllegalArgumentException("Wrong version (" + version + ") in DSA PRIVATE KEY DER stream.");
                }

                final BigInteger p = dr.readInt();
                final BigInteger q = dr.readInt();
                final BigInteger g = dr.readInt();
                final BigInteger y = dr.readInt();
                final BigInteger x = dr.readInt();

                if (dr.available() != 0) {
                    throw new IllegalArgumentException("Padding in DSA PRIVATE KEY DER stream.");
                }

                return generateKeyPair("DSA", new DSAPrivateKeySpec(x, p, q, g), new DSAPublicKeySpec(y, p, q, g));

            case RSA:
                if (version.compareTo(BigInteger.ZERO) != 0 && version.compareTo(BigInteger.ONE) != 0) {
                    throw new IllegalArgumentException("Wrong version (" + version + ") in RSA PRIVATE KEY DER stream.");
                }

                final BigInteger n = dr.readInt();
                final BigInteger e = dr.readInt();
                final BigInteger d = dr.readInt();
                final BigInteger primeP = dr.readInt();
                final BigInteger primeQ = dr.readInt();
                final BigInteger expP = dr.readInt();
                final BigInteger expQ = dr.readInt();
                final BigInteger coeff = dr.readInt();

                return generateKeyPair("RSA",
                        new RSAPrivateCrtKeySpec(n, e, d, primeP, primeQ, expP, expQ, coeff),
                        new RSAPublicKeySpec(n, e));

            case EC:
                if (version.compareTo(BigInteger.ZERO) != 0) {
                    throw new IllegalArgumentException("Wrong version (" + version + ") in EC PRIVATE KEY DER stream.");
                }
                throw new IllegalArgumentException("Not yet");

            default:
                throw new IllegalArgumentException("Unknown key type");
        }
    }

    /**
     * Decrypts the key data.
     * @param data The encrypted data.
     * @param algo The cipher algorithm to use for decryption.
     * @param salt The salt, fetched from the DEK-Info header.
     * @param password The password, specified by the user.
     * @return The decrypted data.
     */
    private byte[] decryptPEM(final byte []data, final KeyAlgo algo, final byte []salt, final byte []password) {
        try {
            Cipher cipher;
            SecretKeySpec keyspec;
            int mks;
            switch (algo) {
                case AES_128_CBC:
                    cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    mks = Cipher.getMaxAllowedKeyLength("AES/CBC/NoPadding");
                    if (mks < 128) {
                        throw new IllegalArgumentException("Maximum key size for AES is " + mks + ". cryptograpy export restrictions?");
                    }
                    keyspec = new SecretKeySpec(generateKeyFromPasswordSaltWithMD5(password, salt, 16), "AES"); // !MAGIC
                    break;
                case AES_192_CBC:
                    cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    mks = Cipher.getMaxAllowedKeyLength("AES/CBC/NoPadding");
                    if (mks < 192) {
                        throw new IllegalArgumentException("Maximum key size for AES is " + mks + ". cryptography export restrictions?");
                    }
                    keyspec = new SecretKeySpec(generateKeyFromPasswordSaltWithMD5(password, salt, 24), "AES"); // !MAGIC
                    break;
                case AES_256_CBC:
                    cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    mks = Cipher.getMaxAllowedKeyLength("AES/CBC/NoPadding");
                    if (mks < 256) {
                        throw new IllegalArgumentException("Maximum key size for AES is " + mks + ". cryptography export restrictions?");
                    }
                    keyspec = new SecretKeySpec(generateKeyFromPasswordSaltWithMD5(password, salt, 32), "AES"); // !MAGIC
                    break;
                case DES_EDE3_CBC:
                    cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                    mks = Cipher.getMaxAllowedKeyLength("DESede/CBC/NoPadding");
                    if (mks < 192) {
                        throw new IllegalArgumentException("Maximum key size for TripleDES is " + mks + ". cryptography export restrictions?");
                    }
                    keyspec = new SecretKeySpec(generateKeyFromPasswordSaltWithMD5(password, salt, 24), "DESede"); // !MAGIC
                    break;
                case DES_CBC:
                    cipher = Cipher.getInstance("DES/CBC/NoPadding");
                    mks = Cipher.getMaxAllowedKeyLength("DES/CBC/NoPadding");
                    if (mks < 64) {
                        throw new IllegalArgumentException("Maximum key size for DES is " + mks + ". cryptography export restrictions?");
                    }
                    keyspec = new SecretKeySpec(generateKeyFromPasswordSaltWithMD5(password, salt, 8), "DES"); // !MAGIC
                    break;
                default:
                    throw new IllegalArgumentException("Invalid key encryption algorithm");
            }
            cipher.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(salt));
            return removePadding(cipher.doFinal(data), cipher.getBlockSize());
        } catch (Throwable t) {
            LOGGER.debug("", t);
            if (t instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) t;
            }
            throw new IllegalArgumentException("Unable to decrypt key data", t);
        }
    }

    /**
     * Removes RFC 1423/PKCS #7 padding.
     * @param data The PKCS#7 padded data.
     * @param blockSize The block size of the decrypting block cipher.
     * @return The data without padding.
     */
    private byte[] removePadding(final byte[] data, final int blockSize) {
        final int padding = data[data.length - 1] & 0xff; // !MAGIC
        final String padError = "Decrypted PEM has wrong padding, did you specify the correct password?";

        if (padding < 1 || padding > blockSize) {
            throw new IllegalArgumentException(padError);
        }
        for (int i = 2; i <= padding; i++) {
            if (data[data.length - i] != padding) {
                throw new IllegalArgumentException(padError);
            }
        }
        byte[] tmp = new byte[data.length - padding];
        System.arraycopy(data, 0, tmp, 0, data.length - padding);
        return tmp;
    }

    /**
     * Generate a secret key for decryption,
     * compatible to OpenSSL's key-generation method.
     * @param password The password, specified by the user.
     * @param salt The salt, fetched from the DEK-Info header.
     * @param keyLen The desired key length.
     * @return A byte array, containing the secret key.
     */
    private byte[] generateKeyFromPasswordSaltWithMD5(final byte[] password, final byte[] salt, final int keyLen) {
        final MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("JVM does not support MD5", e);
        }

        final byte[] key = new byte[keyLen];
        final byte[] tmp = new byte[md5.getDigestLength()];

        int kl = keyLen;
        while (true) {
            md5.update(password, 0, password.length);
            md5.update(salt, 0, 8); // !MAGIC

            int copy = kl < tmp.length ? kl : tmp.length;
            try {
                md5.digest(tmp, 0, tmp.length);
            } catch (Throwable t) {
                throw new IllegalArgumentException("Could not digest password", t);
            }
            System.arraycopy(tmp, 0, key, key.length - kl, copy);
            kl -= copy;
            if (kl <= 0) {
                return key;
            }
            md5.update(tmp, 0, tmp.length);
        }
    }

    /**
     * Generate a KeyPair.
     * @param algorithm The algorithm to use.
     * @param privSpec The private key spec.
     * @param pubSpec The public key spec.
     * @return The generated KeyPair.
     */
    private KeyPair generateKeyPair(final String algorithm, final KeySpec privSpec, final KeySpec pubSpec) {
        try {
            final KeyFactory kf = KeyFactory.getInstance(algorithm);
            final PublicKey pubKey = kf.generatePublic(pubSpec);
            final PrivateKey privKey = kf.generatePrivate(privSpec);
            return new KeyPair(pubKey, privKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalArgumentException(ex);
        }
    }
}
