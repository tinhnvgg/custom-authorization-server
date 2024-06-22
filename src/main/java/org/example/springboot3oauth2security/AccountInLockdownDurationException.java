package org.example.springboot3oauth2security;

import java.io.Serial;

public class AccountInLockdownDurationException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -9146130005545048789L;

    private final long remainingLockdownTime;

    // TODO: implement the message source for super.message
    public AccountInLockdownDurationException(long remainingLockdownTime) {
        this.remainingLockdownTime = remainingLockdownTime;
    }

    public long getRemainingLockdownTime() {
        return remainingLockdownTime;
    }

}
