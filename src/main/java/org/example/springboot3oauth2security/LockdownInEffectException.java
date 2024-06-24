package org.example.springboot3oauth2security;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;

public class LockdownInEffectException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -9146130005545048789L;

    public LockdownInEffectException(long endLockdownTime, String failureUrl) {
        super("LOGIN_LOCKDOWN_IN_EFFECT_MESSAGE", null, failureUrl);
        setMessageParameters(Duration.between(Instant.now(), Instant.ofEpochSecond(endLockdownTime)).toMinutes());
    }

}
