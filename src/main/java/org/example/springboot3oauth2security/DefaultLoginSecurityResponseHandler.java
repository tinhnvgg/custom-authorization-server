package org.example.springboot3oauth2security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

public class DefaultLoginSecurityResponseHandler extends SimpleUrlAuthenticationFailureHandler implements LoginSecurityResponseHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, LoginSecurityException e) throws ServletException, IOException {
        super.setDefaultFailureUrl(e.getAuthenticationFailureUrl() + (e.isIncludeMessage() ? "=" + e.getMessage() : ""));
        super.onAuthenticationFailure(request, response, e);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        this.handle(request, response, new BadCredentialException(e.getCause().getMessage(), e.getMessage(), e.getCause()));
    }

}
