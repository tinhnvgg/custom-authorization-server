package org.example.springboot3oauth2security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class DefaultLoginSecurityResponseHandler implements LoginSecurityResponseHandler {

    @Override
    public void handle(LoginSecurityAction action, HttpServletRequest request, HttpServletResponse response, LoginSecurityException exception) {
        // ------------------------------ handling
    }

}
