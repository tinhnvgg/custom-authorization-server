package org.example.vatisteve.custom.exception;

import org.example.vatisteve.custom.LoginSecurityResponseHandler.LoginSecurityException;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;

import static org.example.vatisteve.custom.exception.ExceptionMessageCode.LOGIN_LOCKDOWN_IN_EFFECT_MESSAGE;

public class LockdownInEffectException extends LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -9146130005545048789L;

    public LockdownInEffectException(Instant endLockdownTime, String failureUrl) {
        super(LOGIN_LOCKDOWN_IN_EFFECT_MESSAGE.getCode(), null, failureUrl);
        setMessageParameters(Duration.between(Instant.now(), endLockdownTime).toMinutes());
    }

}
