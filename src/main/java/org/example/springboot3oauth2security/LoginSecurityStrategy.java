package org.example.springboot3oauth2security;

public interface LoginSecurityStrategy {

    void setUsername(String username);
    long createLockdownDuration();
    long waitingForLockdownDuration();
    int increaseLoginFailureCount();
    boolean passwordHasExpired();

}
