package org.example.springboot3oauth2security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.io.Serial;

public interface LoginSecurityResponseHandler extends AuthenticationFailureHandler {

    void handle(HttpServletRequest request, HttpServletResponse response, LoginSecurityException exception) throws ServletException, IOException;

    abstract class LoginSecurityException extends AuthenticationException {

        @Serial
        private static final long serialVersionUID = 4150324719642480969L;
        private final String authenticationFailureUrl;
        private final boolean includeMessage;

        protected LoginSecurityException(String msg, Throwable cause, String authenticationFailureUrl, boolean includeMessage) {
            super(msg, cause);
            this.authenticationFailureUrl = authenticationFailureUrl;
            this.includeMessage = includeMessage;
        }

        protected LoginSecurityException(String msg, Throwable cause, String authenticationFailureUrl) {
            this(msg, cause, authenticationFailureUrl, true);
        }

        public String getAuthenticationFailureUrl() {
            return authenticationFailureUrl;
        }

        public boolean isIncludeMessage() {
            return includeMessage;
        }

    }

}
