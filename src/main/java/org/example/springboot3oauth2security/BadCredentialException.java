package org.example.springboot3oauth2security;

import java.io.Serial;

public class BadCredentialException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -6201896119543538585L;

    public BadCredentialException(String failureUrl, Throwable trace) {
        super(trace.getMessage(), trace, failureUrl);
    }

    public BadCredentialException(String msg, String failureUrl, Throwable trace) {
        super(msg, trace, failureUrl);
    }

    public BadCredentialException(int remainingLoginFailureCount, Throwable trace) {
        super("Remaining " + remainingLoginFailureCount + " times", trace, null); // TODO: define message
    }

}
