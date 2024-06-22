package org.example.springboot3oauth2security;

import java.time.Instant;

public interface LoginSecurityStrategy {

    void setUsername(String username);
    long createLockdownDuration();
    long waitingForLockdownDuration();
    int increaseLoginFailureCount();
    boolean passwordHasExpired();

    default long getLockdownTime(Instant instant) {
        return instant.getEpochSecond();
    }

}
