package org.example.vatisteve.custom;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.function.Function;

@Getter
@RequiredArgsConstructor
public enum AccountSettingKey {

    /* Periodic password change requirement (days) */
    MAXIMUM_PASSWORD_AGE    ("60"),
    /* Maximum number of allowed failed login attempts */
    MAXIMUM_LOGIN_FAILURE   ("5"),
    /* Account lock time after exceeding the maximum number of failed login attempts (seconds) */
    LOCKDOWN_DURATION       ("300");

    private final String defaultValue;

    public <T> T getDefaultValue(Function<String, T> f) {
        return f.apply(defaultValue);
    }

}
