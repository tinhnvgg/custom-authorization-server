package org.example.springboot3oauth2security;

import java.io.Serial;

public class LockdownInEffectException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -9146130005545048789L;

    public LockdownInEffectException(long remainingLockdownTime, String failureUrl) {
        super("Lockdown in effect", null, failureUrl); // TODO: define message
    }

}
