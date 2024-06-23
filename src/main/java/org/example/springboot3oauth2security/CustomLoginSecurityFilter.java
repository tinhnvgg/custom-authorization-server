package org.example.springboot3oauth2security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

/**
 * <a href="https://github.com/spring-projects/spring-security/issues/10119">
 * This Spring security version does not support to replace default Authentication filter
 * </a>.
 */
public final class CustomLoginSecurityFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * This is a default setting from form login configurer and UsernamePasswordAuthenticationFilter
     */
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");
    private static final String LOGIN_FAILURE_PATH = DEFAULT_ANT_PATH_REQUEST_MATCHER.getPattern() + "?error";
    public static final String CHANGE_PASSWORD_PATH = "/change-password";

    private final LoginSecurityStrategy loginSecurityStrategy;
    private LoginSecurityResponseHandler loginSecurityResponseHandler = new DefaultLoginSecurityResponseHandler();

    public CustomLoginSecurityFilter(AuthenticationManager authenticationManager, LoginSecurityStrategy loginSecurityStrategy) {
        this.loginSecurityStrategy = loginSecurityStrategy;
        this.setAuthenticationFailureHandler(loginSecurityResponseHandler);
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        this.loginSecurityStrategy.setUsername(obtainUsername(request));
        logger.trace("Check the number of failed login attempts and lockdown duration before attempting authentication");
        long remainingLockdownTime = loginSecurityStrategy.waitingForLockdownDuration();
        if (remainingLockdownTime > 0) {
            logger.debug("This current login request is in lockdown time"); // remaining lockdown time > E02
            throw new LockdownInEffectException(remainingLockdownTime, LOGIN_FAILURE_PATH);
        } else {
            return super.attemptAuthentication(request, response);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        logger.trace("Check password expiration after successful authentication");
        if (loginSecurityStrategy.passwordHasExpired()) {
            logger.debug("Redirect to change password page when the password was expired");
            loginSecurityResponseHandler.handle(request, response, new PasswordExpiredException(CHANGE_PASSWORD_PATH));
        } else {
//            super.successfulAuthentication(request, response, chain, authResult);
            // instead of calling super successful authentication method,
            // we should continue to the next filter: UsernamePasswordAuthenticationFilter
            // because we could not replace it
            chain.doFilter(request, response);
        }

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        if (failed instanceof LockdownInEffectException ex) {
            loginSecurityResponseHandler.handle(request, response, ex);
            return;
        }
        logger.trace("Increase failed login attempt count after unsuccessful authentication");
        int remainingLoginFailureCount = loginSecurityStrategy.increaseLoginFailureCount();
        if (remainingLoginFailureCount <= 0) {
            logger.debug("Exceed the allowed number of login attempts");
            long newLockdownTime = loginSecurityStrategy.createLockdownDuration();
            loginSecurityResponseHandler.handle(request, response, new LoginAttemptExceededException(newLockdownTime, failed, LOGIN_FAILURE_PATH));
        } else {
            // The SimpleUrlAuthenticationFailureHandler.defaultFailureUrl has been initialized with FormLoginConfigurer by default,
            // So instead of using default SimpleUrlAuthenticationFailureHandler class,
            // we should use directly LoginSecurityResponseHandler instance as an AuthenticationFailureHandler in this case
            BadCredentialException remainingLoginFailureCountStoreEx = new BadCredentialException(remainingLoginFailureCount, failed);
            super.unsuccessfulAuthentication(request, response, new BadCredentialException(LOGIN_FAILURE_PATH, null, remainingLoginFailureCountStoreEx));
        }
    }

    public void setLoginSecurityResponseHandler(LoginSecurityResponseHandler loginSecurityResponseHandler) {
        this.loginSecurityResponseHandler = loginSecurityResponseHandler;
    }

    public LoginSecurityResponseHandler getLoginSecurityResponseHandler() {
        return loginSecurityResponseHandler;
    }

    public LoginSecurityStrategy getLoginSecurityStrategy() {
        return loginSecurityStrategy;
    }

}
