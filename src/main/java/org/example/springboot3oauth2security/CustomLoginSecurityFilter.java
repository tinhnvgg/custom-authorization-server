package org.example.springboot3oauth2security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

import static org.example.springboot3oauth2security.LoginSecurityResponseHandler.LoginSecurityAction.*;

public final class CustomLoginSecurityFilter extends UsernamePasswordAuthenticationFilter {

    private LoginSecurityStrategy loginSecurityStrategy = new CacheableLoginSecurityStrategy();
    private LoginSecurityResponseHandler loginSecurityResponseHandler = new DefaultLoginSecurityResponseHandler();

    public CustomLoginSecurityFilter(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            super.doFilter(request, response, chain);
        } catch (AccountInLockdownDurationException e) {
            loginSecurityResponseHandler.handle(LOCKDOWN_IN_EFFECT, (HttpServletRequest) request, (HttpServletResponse) response, e);
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, AccountInLockdownDurationException {
        this.loginSecurityStrategy.setUsername(obtainUsername(request));
        logger.trace("Check the number of failed login attempts and lockdown duration before attempting authentication");
        long remainingLockdownTime = loginSecurityStrategy.waitingForLockdownDuration();
        if (remainingLockdownTime > 0) {
            logger.debug("This current login request is in lockdown time"); // remaining lockdown time > E02
            throw new AccountInLockdownDurationException(remainingLockdownTime);
        } else {
            return super.attemptAuthentication(request, response);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        logger.trace("Check password expiration after successful authentication");
        if (loginSecurityStrategy.passwordHasExpired()) {
            logger.debug("Redirect to change password page when the password was expired"); // > E03 > redirection
            loginSecurityResponseHandler.handle(PASSWORD_CHANGE_REQUIRED, request, response, null); // TODO: create an exception class that store the message for change password page
        } else {
            super.successfulAuthentication(request, response, chain, authResult);
        }
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        logger.trace("Increase failed login attempt count after unsuccessful authentication");
        int remainingLoginFailureCount = loginSecurityStrategy.increaseLoginFailureCount();
        if (remainingLoginFailureCount <= 0) {
            logger.debug("Exceed the allowed number of login attempts"); // current counter value and max allowed > E01
            /*long newLockdownTime = */
            loginSecurityStrategy.createLockdownDuration();
            loginSecurityResponseHandler.handle(LOGIN_ATTEMPT_LOCKED, request, response, null); // TODO: create an exception that store the newLockdownTime value
        } else {
            // TODO: add remaining bad credential parameter to response
            super.unsuccessfulAuthentication(request, response, failed);
        }
    }

    public void setLoginSecurityStrategy(LoginSecurityStrategy loginSecurityStrategy) {
        this.loginSecurityStrategy = loginSecurityStrategy;
    }

}
