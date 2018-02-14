package com.graudata.gds2.sslutils;

import static org.junit.Assert.*;

import org.junit.Rule;
import org.junit.Test;

import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

public final class PEMDecoderTest {

    static final Logger LOGGER = LoggerFactory.getLogger(PEMDecoderTest.class);

    @Rule
    final public TestRule traceTestWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description d) {
            LOGGER.info("Starting Test: {}", d);
        }

        @Override
        protected void finished(final Description d) {
            LOGGER.info("Finished Test: {}", d);
        }
    };

    private RSAPrivateCrtKeySpec decodeKeyFileWithOpenssl(final String keyfile) throws IOException {
        final List<String> cmd = new ArrayList<String>();
        cmd.add("openssl");
        cmd.add("rsa");
        cmd.add("-noout");
        cmd.add("-text");
        cmd.add("-in");
        cmd.add(keyfile);
        final ProcessBuilder pb = new ProcessBuilder(cmd);
        final Process process = pb.start();
        try (final InputStreamReader isr = new InputStreamReader(process.getInputStream(), Charset.defaultCharset());
                final BufferedReader br = new BufferedReader(isr); )
        {
            String line;
            StringBuilder hexbuf = new StringBuilder();
            String tag = "";
            boolean fetchhex = false;
            BigInteger modulus = null;
            BigInteger publicExponent = null;
            BigInteger privateExponent = null;
            BigInteger primeP = null;
            BigInteger primeQ = null;
            BigInteger primeExponentP = null;
            BigInteger primeExponentQ = null;
            BigInteger crtCoefficient = null;
            while ((line = br.readLine()) != null) {
                if (fetchhex) {
                    // collect hexdump lines.
                    if (line.startsWith("    ")) {
                        hexbuf.append(line.trim().replaceAll(":",""));
                        continue;
                    } else {
                        fetchhex = false;
                        BigInteger bi = new BigInteger(hexbuf.toString(), 16);
                        // Store it according to its tag.
                        if (tag.equals("modulus:")) {
                            modulus = bi;
                        }
                        if (tag.equals("privateExponent:")) {
                            privateExponent = bi;
                        }
                        if (tag.equals("prime1:")) {
                            primeP = bi;
                        }
                        if (tag.equals("prime2:")) {
                            primeQ = bi;
                        }
                        if (tag.equals("exponent1:")) {
                            primeExponentP = bi;
                        }
                        if (tag.equals("exponent2:")) {
                            primeExponentQ = bi;
                        }
                        if (tag.equals("coefficient:")) {
                            crtCoefficient = bi;
                        }
                    }
                }
                tag = line.trim();
                // Those are printed as hexdumps by openssl.
                if (tag.matches("(modulus:)|(privateExponent:)|(prime1:)|(prime2:)|(exponent1:)|(exponent2:)|(coefficient:)")) {
                    fetchhex = true;
                    hexbuf.setLength(0);
                    continue;
                }
                // This one is printed as two numbers (decimal and binary) by openssl
                if (tag.startsWith("publicExponent:")) {
                    String []nr = tag.substring(15).trim().split("\\s+");
                    publicExponent = new BigInteger(nr[0], 10);
                }
            }
            if (fetchhex) {
                BigInteger bi = new BigInteger(hexbuf.toString(), 16);
                // Store it according to its tag.
                if (tag.equals("modulus:")) {
                    modulus = bi;
                }
                if (tag.equals("privateExponent:")) {
                    privateExponent = bi;
                }
                if (tag.equals("prime1:")) {
                    primeP = bi;
                }
                if (tag.equals("prime2:")) {
                    primeQ = bi;
                }
                if (tag.equals("exponent1:")) {
                    primeExponentP = bi;
                }
                if (tag.equals("exponent2:")) {
                    primeExponentQ = bi;
                }
                if (tag.equals("coefficient:")) {
                    crtCoefficient = bi;
                }
            }
            return new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent,
                    primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
        }
    }

    /**
     * Reads a whole file resource into a String.
     * @param path The path of the resource to read.
     * @return A String, holding the whole content (empty if the resource was not found).
     */
    private String readPEMResource(final String path) {
        
        try (
                final InputStream is = getClass().getClassLoader().getResourceAsStream(path);
                final Scanner s = new Scanner(is, "UTF-8").useDelimiter("\\A");
        ) {
            return s.hasNext() ? s.next() : "";
        } catch (NullPointerException | IOException e) {
            return "";
        }

    }

    private RSAPrivateCrtKeySpec decodeKeyResourceWithOpenssl(final String path) throws IOException, FileNotFoundException {
        try {
            // openssl requires a file in the filesystem. So create a temporary one here.
            final File tmpf = File.createTempFile(getClass().getSimpleName(), ".pem");
            tmpf.deleteOnExit();
            final PrintWriter pw = new PrintWriter(tmpf, "UTF-8");
            pw.print(readPEMResource(path));
            pw.close();
            return decodeKeyFileWithOpenssl(tmpf.getAbsolutePath());
        } catch (Throwable t) {
            LOGGER.warn("", t);
            throw t;
        }
    }

    @Test
    public void testAES128EncryptedKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key.aes128");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testAES192EncryptedKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key.aes192");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testAES256EncryptedKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key.aes256");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testDESEncryptedKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key.des");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testTripleDESEncryptedKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key.des3");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testPlainKey() throws IOException {
        RSAPrivateCrtKeySpec refk = decodeKeyResourceWithOpenssl("devel.agorum.dataspace.cc.key");
        assertNotNull("Reference key is null", refk);
        final String s = readPEMResource("devel.agorum.dataspace.cc.key");
        assertNotNull("Input PEM is null", s);
        final PEMDecoder pd = new PEMDecoder();
        final KeyPair kp = pd.decodePrivKey(s, "iSINm4neBosw");
        assertNotNull("Decoded keyPair is null", kp);
        final RSAPrivateCrtKey p = (RSAPrivateCrtKey)kp.getPrivate();
        assertNotNull("Decoded private key is null", p);
        assertEquals("modulus of reference and decoded private key differ", refk.getModulus(), p.getModulus());
        assertEquals("publicExponent of reference and decoded private key differ", refk.getPublicExponent(), p.getPublicExponent());
        assertEquals("privateExponent of reference and decoded private key differ", refk.getPrivateExponent(), p.getPrivateExponent());
        assertEquals("primeP of reference and decoded private key differ", refk.getPrimeP(), p.getPrimeP());
        assertEquals("primeQ of reference and decoded private key differ", refk.getPrimeQ(), p.getPrimeQ());
        assertEquals("primeExponentP of reference and decoded private key differ", refk.getPrimeExponentP(), p.getPrimeExponentP());
        assertEquals("primeExponentQ of reference and decoded private key differ", refk.getPrimeExponentQ(), p.getPrimeExponentQ());
        assertEquals("crtCoefficient of reference and decoded private key differ", refk.getCrtCoefficient(), p.getCrtCoefficient());
    }

    @Test
    public void testSingleCert() throws ParseException {
        boolean thrown = false;
        Collection<? extends Certificate> cl = null;
        try {
            final String s = readPEMResource("devel.agorum.dataspace.cc.crt");
            final PEMDecoder pd = new PEMDecoder();
            cl = pd.decodeCertificates(s);
        } catch (Throwable t) {
            thrown = true;
        }
        assertFalse("Thrown an exception", thrown);
        assertEquals("Number of certificates", 1, cl.size());
        final X509Certificate c = cl.toArray(new X509Certificate [1])[0];
        final X500Principal issuer = c.getIssuerX500Principal();
        final X500Principal subject = c.getSubjectX500Principal();
        assertEquals("Subject", "EMAILADDRESS=hostmaster@dataspace.cc, CN=devel.agorum.dataspace.cc, C=DE, OID.2.5.4.13=weReAP2caL2zzi9c", subject.toString());
        assertEquals("Issuer", "CN=StartCom Class 1 Primary Intermediate Server CA, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL", issuer.toString());
        assertEquals("Serial", new BigInteger("822156", 10), c.getSerialNumber());
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, Locale.GERMANY);
        Date refdate = df.parse("21.10.2013 07:54:46");
        assertEquals("Not before", refdate, c.getNotBefore());
        refdate = df.parse("22.10.2014 06:28:32");
        assertEquals("Not after", refdate, c.getNotAfter());
    }

    @Test
    public void testMultipleCerts() {
        boolean thrown = false;
        Collection<? extends Certificate> cl = null;
        try {
            final String s = readPEMResource("startcom-bundle.pem");
            final PEMDecoder pd = new PEMDecoder();
            cl = pd.decodeCertificates(s);
        } catch (Throwable t) {
            thrown = true;
        }
        assertFalse("Thrown an exception", thrown);
        assertEquals("Number of certificates", 2, cl.size());
        final String[] refSubject = {
            "CN=StartCom Class 1 Primary Intermediate Server CA, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL",
            "CN=StartCom Certification Authority, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL"
        };
        final String[] refIssuer = {
            "CN=StartCom Certification Authority, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL",
            "CN=StartCom Certification Authority, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL"
        };
        int refIdx = 0;
        for (final Certificate tmpc : cl) {
            final X509Certificate c = (X509Certificate) tmpc;
            final X500Principal issuer = c.getIssuerX500Principal();
            final X500Principal subject = c.getSubjectX500Principal();
            assertEquals("Subject", refSubject[refIdx], subject.toString());
            assertEquals("Issuer", refIssuer[refIdx], issuer.toString());
            refIdx++;
        }
    }

}
