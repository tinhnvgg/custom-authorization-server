package org.example.vatisteve.controller;

import org.example.vatisteve.custom.implement.DefaultLoginSecurityStrategy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;

@Controller
public class Oauth2AuthorizationServerController {

    private final UserDetailsManager userDetailsManager;

    public Oauth2AuthorizationServerController(UserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    @GetMapping("/login")
    public String login() {
        return "views/login";
    }

    @GetMapping("/logout")
    public String logout() {
        return "views/logout";
    }

    @GetMapping("/change-password")
    public String changePasswordPage() {
        return "views/change-password";
    }

    @PostMapping("/change-password")
    public String changePasswordPost(@RequestParam String password) {
        doChangePassword(SecurityContextHolder.getContext().getAuthentication().getName(), password);
        return "redirect:/login?password-changed";
    }

    private void doChangePassword(String name, String password) {
        UserDetails userDetails = userDetailsManager.loadUserByUsername(name);
        userDetailsManager.changePassword(userDetails.getPassword(), "{noop}" + password);
        new DefaultLoginSecurityStrategy.SampleLoginSecurityCache().updatePasswordLastModified(name, Instant.now());
    }

}
