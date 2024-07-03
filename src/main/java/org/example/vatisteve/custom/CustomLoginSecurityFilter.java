package org.example.vatisteve.custom;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.example.vatisteve.custom.LoginSecurityStrategy.LoginSecuritySettingsStore;
import org.example.vatisteve.custom.exception.BadCredentialException;
import org.example.vatisteve.custom.exception.LockdownInEffectException;
import org.example.vatisteve.custom.exception.LoginAttemptExceededException;
import org.example.vatisteve.custom.exception.PasswordExpiredException;
import org.example.vatisteve.custom.implement.DefaultLoginSecurityResponseHandler;
import org.example.vatisteve.custom.implement.DefaultLoginSecurityStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;
import java.time.Instant;

/**
 * <a href="https://github.com/spring-projects/spring-security/issues/10119">
 * This Spring security version does not support to replace default Authentication filter
 * </a>.
 */
@Setter
@Getter
public final class CustomLoginSecurityFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * This is a default setting from form login configurer and UsernamePasswordAuthenticationFilter
     */
    private String loginPage = "/login";
    private String changePasswordPage = "/change-password";
    private String errorKeyParameter = "error";

    private final LoginSecurityStrategy loginSecurityStrategy;
    private LoginSecurityResponseHandler loginSecurityResponseHandler = new DefaultLoginSecurityResponseHandler();

    public CustomLoginSecurityFilter(AuthenticationManager authenticationManager,
                                     LoginSecuritySettingsStore settingsStore,
                                     SecurityContextRepository securityContextRepository) {
        this.setAuthenticationFailureHandler(loginSecurityResponseHandler);
        this.loginSecurityStrategy = new DefaultLoginSecurityStrategy(settingsStore, true);
        setAuthenticationManager(authenticationManager);
        setSecurityContextRepository(securityContextRepository);
    }

    private String getLoginFailurePath() {
        return loginPage + "?" + errorKeyParameter;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        this.loginSecurityStrategy.setUsername(obtainUsername(request));
        logger.trace("Check the lockdown duration before attempting authentication");
        Instant endLockDownTime = loginSecurityStrategy.waitingForLockdownDuration();
        if (endLockDownTime != null) {
            logger.debug("This current login request is in lockdown time");
            throw new LockdownInEffectException(endLockDownTime, getLoginFailurePath());
        } else {
            return super.attemptAuthentication(request, response);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        loginSecurityStrategy.clear(); // when login successfully
        logger.trace("Check password expiration after successful authentication");
        if (loginSecurityStrategy.passwordHasExpired()) {
            logger.debug("Redirect to change password page when the password was expired");
            // Save security context and then redirecting to change-password page
            // Use super onSuccessfulAuthentication method with a Non-authentication-success-handler
            // Be careful to remove this authentication-success-handler setting when above issues is solved
            super.setAuthenticationSuccessHandler((request1, response1, authentication) -> {/* do nothing */});
            super.successfulAuthentication(request, response, chain, authResult);
            loginSecurityResponseHandler.handle(request, response, new PasswordExpiredException(changePasswordPage));
        } else {
/*            super.successfulAuthentication(request, response, chain, authResult);*/
            // Instead of calling super successful authentication method,
            // we should let the request continue to the next filter (UsernamePasswordAuthenticationFilter)
            // which is the default filter and could not be removed by configuration
            chain.doFilter(request, response);
        }

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        if (failed instanceof LockdownInEffectException ex) {
            logger.trace("Handle login request for account in lockdown time");
            loginSecurityResponseHandler.handle(request, response, ex);
            return;
        }
        logger.trace("Increase failed login attempt count after unsuccessful authentication");
        int remainingLoginFailureCount = loginSecurityStrategy.increaseLoginFailureCount();
        if (remainingLoginFailureCount <= 0) {
            logger.debug("Exceed the allowed number of login attempts");
            Instant newLockdownTime = loginSecurityStrategy.createLockdownDuration();
            loginSecurityResponseHandler.handle(request, response, new LoginAttemptExceededException(newLockdownTime, failed, getLoginFailurePath()));
        } else {
            // The SimpleUrlAuthenticationFailureHandler.defaultFailureUrl has been initialized with FormLoginConfigurer by default,
            // So instead of using default SimpleUrlAuthenticationFailureHandler class,
            // we should use directly LoginSecurityResponseHandler instance as an AuthenticationFailureHandler in this case
            BadCredentialException remainingLoginFailureCountStoreEx = new BadCredentialException(remainingLoginFailureCount, failed);
            super.unsuccessfulAuthentication(request, response, new BadCredentialException(getLoginFailurePath(), null, remainingLoginFailureCountStoreEx));
        }
    }

}
