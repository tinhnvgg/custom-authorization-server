package org.example.springboot3oauth2security;

import org.springframework.security.core.AuthenticationException;

import java.io.Serial;

public class LoginAttemptExceededException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -3120896252867471679L;

    public LoginAttemptExceededException(long lockdownDuration, AuthenticationException trace, String failurePath) {
        super("Login attempt exceeded", trace, failurePath); // TODO: define message
    }

}
