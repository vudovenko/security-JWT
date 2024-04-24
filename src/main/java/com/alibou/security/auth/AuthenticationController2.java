package com.alibou.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/api/v1/auth2")
@RequiredArgsConstructor
public class AuthenticationController2 {

    private final AuthenticationService service;

    @GetMapping("/signup-page")
    public String registration(Model model) {
        model.addAttribute("registrationForm", new RegisterRequest());
        return "singup_page";
    }

    @PostMapping("/register")
    public String registration(RegisterRequest request, Model model) {
        service.register(request);
        model.addAttribute("authenticationRequest", new AuthenticationRequest());
        return "redirect:/api/v1/auth2/login-page";
    }

    @GetMapping("/login-page")
    public String getLoginPage(HttpServletResponse httpServletResponse, Model model) {
        model.addAttribute("authenticationRequest", new AuthenticationRequest());
        return "login_page";
    }

    @PostMapping("/authenticate")
    public String authenticate(
            AuthenticationRequest request,
            HttpServletResponse httpServletResponse) {
        AuthenticationResponse authenticationResponse = service.authenticate(request);
        Cookie cookie = new Cookie("token", authenticationResponse.getToken());
        cookie.setPath("/");
        httpServletResponse.addCookie(cookie);
        return "redirect:/api/v1/index-controller/index";
    }
}
