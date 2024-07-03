package org.example.vatisteve.custom;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public interface LoginSecurityStrategy {

    void setUsername(String username);
    String getUsername();

    int maximumPasswordAge();
    int maximumLoginFailureAttempts();
    long lockdownDuration();
    LoginSecuritySettingsStore getSettingStore();

    default Instant createLockdownDuration() {
        Instant endLockdownTime = Instant.now().plusSeconds(lockdownDuration());
        getSettingStore().updateEndLockdownTime(getUsername(), endLockdownTime);
        return endLockdownTime;
    }

    default Instant waitingForLockdownDuration() {
        Instant now = Instant.now();
        Instant endLockdownTime = getSettingStore().getEndLockdownTime(getUsername()).orElse(now);
        if (endLockdownTime.isAfter(now)) return endLockdownTime;
        getSettingStore().evictEndLockdownTime(getUsername());
        return null;
    }

    default int increaseLoginFailureCount() {
        int failureCount = getSettingStore().getNumberOfLoginFailureCount(getUsername()).orElse(0) + 1;
        if (failureCount < maximumLoginFailureAttempts()) {
            getSettingStore().updateLoginFailureCount(getUsername(), failureCount);
            return maximumLoginFailureAttempts() - failureCount;
        } else {
            getSettingStore().evictLoginFailureCount(getUsername());
            return 0;
        }
    }

    default boolean passwordHasExpired() {
        Instant now = Instant.now();
        Instant lastChangedPass = getSettingStore().getPasswordLastModified(getUsername()).orElse(now);
        return now.isAfter(lastChangedPass.plus(maximumPasswordAge(), ChronoUnit.DAYS));
    }

    default void clear() {
        getSettingStore().evictLoginFailureCount(getUsername());
    }

    interface LoginSecuritySettingsStore {
        default int maximumPasswordAge(String username) {
            throw new UnsupportedOperationException("Maximum password age must be overridden with custom LoginSecurityStrategy");
        }
        default int maximumLoginFailureAttempts(String username) {
            throw new UnsupportedOperationException("Maximum login failure attempts must be overridden with custom LoginSecurityStrategy");
        }
        default long lockdownDuration(String username) {
            throw new UnsupportedOperationException("Lockdown duration must be overridden with custom LoginSecurityStrategy");
        }
        void updateEndLockdownTime(String username, Instant endLockdownTime);
        Optional<Instant> getEndLockdownTime(String username);
        void evictEndLockdownTime(String username);
        void updateLoginFailureCount(String username, int loginFailureAttempts);
        Optional<Integer> getNumberOfLoginFailureCount(String username);
        void evictLoginFailureCount(String username);
        Optional<Instant> getPasswordLastModified(String username);
        void updatePasswordLastModified(String username, Instant passwordLastModified);
    }

}
