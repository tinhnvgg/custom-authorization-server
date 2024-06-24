package org.example.springboot3oauth2security.exception;

import org.example.springboot3oauth2security.custom.LoginSecurityResponseHandler;
import org.springframework.security.core.AuthenticationException;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;

public class LoginAttemptExceededException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -3120896252867471679L;

    public LoginAttemptExceededException(long endLockdownTime, AuthenticationException trace, String failurePath) {
        super("EXCEED_ALLOW_LOGIN_ATTEMPTS_COUNT_MESSAGE", trace, failurePath);
        setMessageParameters(Duration.between(Instant.now(), Instant.ofEpochSecond(endLockdownTime)).toMinutes());
    }

}
