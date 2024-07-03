package org.example.vatisteve.custom.exception;

import org.example.vatisteve.custom.LoginSecurityResponseHandler.LoginSecurityException;

import java.io.Serial;

import static org.example.vatisteve.custom.exception.ExceptionMessageCode.PASSWORD_CHANGE_REQUIRED_MESSAGE;

public class PasswordExpiredException extends LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -6504829636309671086L;

    public PasswordExpiredException(String changePasswordPath) {
        super(PASSWORD_CHANGE_REQUIRED_MESSAGE.getCode(), null, changePasswordPath, false);
    }

}
