package org.example.vatisteve.custom.exception;

import org.example.vatisteve.custom.LoginSecurityResponseHandler.LoginSecurityException;

import java.io.Serial;

import static org.example.vatisteve.custom.exception.ExceptionMessageCode.BAD_CREDENTIAL_MESSAGE;

public class BadCredentialException extends LoginSecurityException {

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
        super(BAD_CREDENTIAL_MESSAGE.getCode(), trace, null);
        setMessageParameters(remainingLoginFailureCount);
    }

}
