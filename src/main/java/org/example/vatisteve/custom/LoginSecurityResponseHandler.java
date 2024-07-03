package org.example.vatisteve.custom;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.context.MessageSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.io.Serial;

public interface LoginSecurityResponseHandler extends AuthenticationFailureHandler {

    void setMessageSource(final MessageSource messageSource);

    void handle(HttpServletRequest request, HttpServletResponse response, LoginSecurityException exception) throws ServletException, IOException;

    @Getter
    abstract class LoginSecurityException extends AuthenticationException {

        @Serial
        private static final long serialVersionUID = 4150324719642480969L;
        private final String authenticationFailureUrl;
        private final boolean includeMessage;
        private transient Object[] messageParameters;

        protected LoginSecurityException(String msg, Throwable cause, String authenticationFailureUrl, boolean includeMessage) {
            super(msg, cause);
            this.authenticationFailureUrl = authenticationFailureUrl;
            this.includeMessage = includeMessage;
        }

        protected LoginSecurityException(String msg, Throwable cause, String authenticationFailureUrl) {
            this(msg, cause, authenticationFailureUrl, true);
        }

        protected void setMessageParameters(Object... messageParameters) {
            this.messageParameters = messageParameters;
        }

    }

}
