package org.example.vatisteve.custom.implement;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.example.vatisteve.custom.AccountSettingKey;
import org.example.vatisteve.custom.LoginSecurityStrategy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Setter
@Getter
@RequiredArgsConstructor
public class DefaultLoginSecurityStrategy implements LoginSecurityStrategy {

    private String username = "";
    private final LoginSecuritySettingsStore settingStore;
    private final boolean useGlobalSettings;

    @Override
    public int maximumPasswordAge() {
        if (useGlobalSettings) return AccountSettingKey.MAXIMUM_PASSWORD_AGE.getDefaultValue(Integer::parseInt);
        return settingStore.maximumPasswordAge(username);
    }

    @Override
    public int maximumLoginFailureAttempts() {
        if (useGlobalSettings) return AccountSettingKey.MAXIMUM_LOGIN_FAILURE.getDefaultValue(Integer::parseInt);
        return settingStore.maximumLoginFailureAttempts(username);
    }

    @Override
    public long lockdownDuration() {
        if (useGlobalSettings) return AccountSettingKey.LOCKDOWN_DURATION.getDefaultValue(Long::parseLong);
        return settingStore.lockdownDuration(username);
    }

    // Sample settings ------------------------------------------------------------------------------------------------
    @SuppressWarnings("unused")
    public static class SampleLoginSecurityCache implements LoginSecuritySettingsStore {

        static final Map<String, Instant> LOCKDOWN_DURATION_CACHE = new ConcurrentHashMap<>();
        static final Map<String, Integer> LOGIN_FAILURE_ATTEMPTS_CACHE = new ConcurrentHashMap<>();
        static final Map<String, Instant> LAST_CHANGED_PASS_CACHE = new ConcurrentHashMap<>();

        static {
            LAST_CHANGED_PASS_CACHE.put("user", Instant.now().minus(
                    AccountSettingKey.LOCKDOWN_DURATION.getDefaultValue(Long::parseLong) + 1,
                    ChronoUnit.DAYS)
            );
        }

        @Override
        public void updateEndLockdownTime(String username, Instant endLockdownTime) {
            LOCKDOWN_DURATION_CACHE.put(username, endLockdownTime);
        }

        @Override
        public Optional<Instant> getEndLockdownTime(String username) {
            return Optional.ofNullable(LOCKDOWN_DURATION_CACHE.get(username));
        }

        @Override
        public void evictEndLockdownTime(String username) {
            LOCKDOWN_DURATION_CACHE.remove(username);
        }

        @Override
        public void updateLoginFailureCount(String username, int loginFailureAttempts) {
            LOGIN_FAILURE_ATTEMPTS_CACHE.put(username, loginFailureAttempts);
        }

        @Override
        public Optional<Integer> getNumberOfLoginFailureCount(String username) {
            return Optional.of(LOGIN_FAILURE_ATTEMPTS_CACHE.getOrDefault(username, 0));
        }

        @Override
        public void evictLoginFailureCount(String username) {
            LOGIN_FAILURE_ATTEMPTS_CACHE.remove(username);
        }

        @Override
        public void updatePasswordLastModified(String username, Instant lastChangedPass) {
            LAST_CHANGED_PASS_CACHE.put(username, lastChangedPass);
        }

        @Override
        public Optional<Instant> getPasswordLastModified(String username) {
            return Optional.of(LAST_CHANGED_PASS_CACHE.getOrDefault(username, Instant.now()));
        }
    }
    // ----------------------------------------------------------------------------------------------------------------

}