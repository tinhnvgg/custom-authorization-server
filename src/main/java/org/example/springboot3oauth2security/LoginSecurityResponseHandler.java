package org.example.springboot3oauth2security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.Serial;

public interface LoginSecurityResponseHandler {

    void handle(LoginSecurityAction action, HttpServletRequest request, HttpServletResponse response, LoginSecurityException exception);

    enum LoginSecurityAction {
        PASSWORD_CHANGE_REQUIRED,   // when the user logs in successfully but needs to change their expired password.
        LOGIN_ATTEMPT_LOCKED,       // when the user has exceeded the maximum number of invalid login attempts.
        LOCKDOWN_IN_EFFECT          // when the user is attempting to log in during a lockdown period.
    }

    class LoginSecurityException extends RuntimeException {
        @Serial
        private static final long serialVersionUID = -1;
    }

}
