package org.example.vatisteve.custom.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ExceptionMessageCode {

    BAD_CREDENTIAL_MESSAGE                      ("login.message.bad-credential"),
    LOGIN_LOCKDOWN_IN_EFFECT_MESSAGE            ("login.message.lockdown-in-effect"),
    EXCEED_ALLOW_LOGIN_ATTEMPTS_COUNT_MESSAGE   ("login.message.exceed-allow-login-attempts-count"),
    PASSWORD_CHANGE_REQUIRED_MESSAGE            ("login.message.password-change-required");

    private final String code;

}
