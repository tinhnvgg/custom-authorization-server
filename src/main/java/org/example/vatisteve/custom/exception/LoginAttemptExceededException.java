package org.example.vatisteve.custom.exception;

import org.example.vatisteve.custom.LoginSecurityResponseHandler.LoginSecurityException;
import org.springframework.security.core.AuthenticationException;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;

import static org.example.vatisteve.custom.exception.ExceptionMessageCode.EXCEED_ALLOW_LOGIN_ATTEMPTS_COUNT_MESSAGE;

public class LoginAttemptExceededException extends LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -3120896252867471679L;

    public LoginAttemptExceededException(Instant endLockdownTime, AuthenticationException trace, String failurePath) {
        super(EXCEED_ALLOW_LOGIN_ATTEMPTS_COUNT_MESSAGE.getCode(), trace, failurePath);
        setMessageParameters(Duration.between(Instant.now(), endLockdownTime).toMinutes());
    }

}
