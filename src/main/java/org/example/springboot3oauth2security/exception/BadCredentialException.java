package org.example.springboot3oauth2security.exception;

import org.example.springboot3oauth2security.custom.LoginSecurityResponseHandler;

import java.io.Serial;

public class BadCredentialException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -6201896119543538585L;

    public BadCredentialException(String msg, String failureUrl, Throwable trace) {
        super(msg, trace, failureUrl);
        if (trace instanceof BadCredentialException e) setMessageParameters(e.getMessageParameters());
    }

    public BadCredentialException(String failureUrl, Throwable trace) {
        this(trace.getMessage(), failureUrl, trace);
    }

    public BadCredentialException(int remainingLoginFailureCount, Throwable trace) {
        super("BAD_CREDENTIAL_MESSAGE", trace, null);
        setMessageParameters(remainingLoginFailureCount);
    }

}
