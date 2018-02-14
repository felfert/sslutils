package com.github.felfert.sslutils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * A HostnameVerifyer which accepts an host name.
 */
public final class AnyHostnameVerifier implements HostnameVerifier {

    /**
     * {@inheritDoc}
     */
    public boolean verify(final String hostname, final SSLSession session) {
        return true;
    }
}
