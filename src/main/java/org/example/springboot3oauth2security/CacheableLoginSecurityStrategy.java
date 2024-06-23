package org.example.springboot3oauth2security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.example.springboot3oauth2security.SampleCache.*;

@Component
public class CacheableLoginSecurityStrategy implements LoginSecurityStrategy {

    private String username = "";

    // Sample settings ------------------------------------------------------------------------------------------------
    private static final int MAXIMUM_PASSWORD_AGE = 60;             // DAYS
    private static final int MAXIMUM_LOGIN_FAILURE_ATTEMPTS = 5;    // TIMES
    private static final long LOCKDOWN_DURATION = 5L * 60;           // SECONDS
    private SampleLoginSecurityCache loginSecurityCache;

    @Autowired
    public void setLoginSecurityCache(SampleLoginSecurityCache loginSecurityCache) {
        this.loginSecurityCache = loginSecurityCache;
    }

    @Component
    public static class SampleLoginSecurityCache {

//        @CachePut(cacheNames = "LOCKDOWN_DURATION", key = "#username")
        public void updateEndLockdownTime(String username, long endLockdownTime) {
            LOCKDOWN_DURATION_CACHE.put(username, endLockdownTime);
        }

//        @Cacheable(cacheNames = "LOCKDOWN_DURATION", unless="#result == null")
        public Optional<Long> getEndLockdownTime(String username) {
            return Optional.of(LOCKDOWN_DURATION_CACHE.getOrDefault(username, 0L));
        }

//        @CacheEvict(cacheNames = "LOCKDOWN_DURATION")
        public void evictEndLockdownTime(String username) {
            LOCKDOWN_DURATION_CACHE.remove(username);
        }

//        @CachePut(cacheNames = "LOGIN_FAILURE_ATTEMPTS", key = "#username")
        public void updateLoginFailureAttempts(String username, int loginFailureAttempts) {
            LOGIN_FAILURE_ATTEMPTS_CACHE.put(username, loginFailureAttempts);
        }

//        @Cacheable(cacheNames = "LOGIN_FAILURE_ATTEMPTS", unless="#result == null")
        public Optional<Integer> getNumberOfLoginFailureCount(String username) {
            return Optional.of(LOGIN_FAILURE_ATTEMPTS_CACHE.getOrDefault(username, 0));
        }

//        @CacheEvict(cacheNames = "LOGIN_FAILURE_ATTEMPTS")
        public void evictLoginFailureAttempts(String username) {
            LOGIN_FAILURE_ATTEMPTS_CACHE.remove(username);
        }

//        @CachePut(cacheNames = "LAST_CHANGED_PASS", key = "#username")
        public void updateLastChangedPass(String username, Instant lastChangedPass) {
            LAST_CHANGED_PASS_CACHE.put(username, lastChangedPass);
        }

//        @Cacheable(cacheNames = "LAST_CHANGED_PASS", unless="#result == null")
        public Optional<Instant> getLastChangedPassword(String username) {
            return Optional.of(LAST_CHANGED_PASS_CACHE.getOrDefault(username, Instant.now()));
        }

    }
    // ----------------------------------------------------------------------------------------------------------------

    @Override
    public void setUsername(String username) {
        this.username = username != null ? username : "";
    }

    @Override
    public long createLockdownDuration() {
        long endLockdownTime = getLockdownTime(Instant.now().plusSeconds(LOCKDOWN_DURATION));
        loginSecurityCache.updateEndLockdownTime(username, endLockdownTime);
        return endLockdownTime;
    }

    @Override
    public long waitingForLockdownDuration() {
        long endLockdownTime = loginSecurityCache.getEndLockdownTime(username).orElse(getLockdownTime(Instant.now()));
        if (endLockdownTime < getLockdownTime(Instant.now())) {
            loginSecurityCache.evictEndLockdownTime(username);
            return 0;
        }
        return endLockdownTime;
    }

    @Override
    public int increaseLoginFailureCount() {
        int failureCount = loginSecurityCache.getNumberOfLoginFailureCount(username).orElse(0);
        if (failureCount < MAXIMUM_LOGIN_FAILURE_ATTEMPTS) {
            loginSecurityCache.updateLoginFailureAttempts(username, ++failureCount);
            return MAXIMUM_LOGIN_FAILURE_ATTEMPTS - failureCount;
        } else {
            loginSecurityCache.evictLoginFailureAttempts(username);
            return 0;
        }
    }

    @Override
    public boolean passwordHasExpired() {
        Instant lastChangedPass = loginSecurityCache.getLastChangedPassword(username).orElse(Instant.now());
        return lastChangedPass.plus(MAXIMUM_PASSWORD_AGE, ChronoUnit.DAYS).isBefore(Instant.now());
    }

}