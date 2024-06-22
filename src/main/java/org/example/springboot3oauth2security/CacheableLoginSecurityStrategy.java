package org.example.springboot3oauth2security;

public class CacheableLoginSecurityStrategy implements LoginSecurityStrategy {

    private String username = "";

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public long createLockdownDuration() {
        return 0;
    }

    @Override
    public long waitingForLockdownDuration() {
        return 0;
    }

    @Override
    public int increaseLoginFailureCount() {
        return 0;
    }

    @Override
    public boolean passwordHasExpired() {
        return false;
    }

}
