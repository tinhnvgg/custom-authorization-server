package org.example.springboot3oauth2security;

import java.io.Serial;

public class PasswordExpiredException extends LoginSecurityResponseHandler.LoginSecurityException {

    @Serial
    private static final long serialVersionUID = -6504829636309671086L;

    public PasswordExpiredException(String changePasswordPath) {
        super("PASSWORD_CHANGE_REQUIRED_MESSAGE", null, changePasswordPath, false);
    }

}
