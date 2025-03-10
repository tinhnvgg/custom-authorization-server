package org.example.vatisteve.custom.implement;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.example.vatisteve.custom.LoginSecurityResponseHandler;
import org.example.vatisteve.custom.exception.BadCredentialException;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Setter
public class DefaultLoginSecurityResponseHandler extends SimpleUrlAuthenticationFailureHandler implements LoginSecurityResponseHandler {

    private MessageSource messageSource;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, LoginSecurityException e) throws ServletException, IOException {
        super.setDefaultFailureUrl(e.getAuthenticationFailureUrl() + (e.isIncludeMessage() ? getMessageValue(e) : ""));
        super.onAuthenticationFailure(request, response, e);
    }

    private String getMessageValue(LoginSecurityException e) {
        return "=" + Optional.ofNullable(messageSource)
                .map(m -> messageSource.getMessage(e.getMessage(), e.getMessageParameters(), LocaleContextHolder.getLocale()))
                .map(m -> UriUtils.encodePath(m, StandardCharsets.UTF_8))
                .orElse(e.getMessage());
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        this.handle(request, response, new BadCredentialException(e.getCause().getMessage(), e.getMessage(), e.getCause()));
    }

}
