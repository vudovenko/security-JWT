package com.alibou.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            AuthenticationRequest request,
            HttpServletResponse httpServletResponse) {

        AuthenticationResponse authenticationResponse = service.authenticate(request);
        Cookie cookie = new Cookie("token", authenticationResponse.getToken());
        cookie.setPath("/");
        httpServletResponse.addCookie(cookie);
        return ResponseEntity.ok(authenticationResponse);
    }

//  @PostMapping("/refresh-token")
//  public void refreshToken(
//      HttpServletRequest request,
//      HttpServletResponse response
//  ) throws IOException {
//    service.refreshToken(request, response);
//  }


}
