package com.spring.security.controller;

import com.spring.security.models.dtos.LoginDTO;
import com.spring.security.persistence.entity.User;
import com.spring.security.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    ResponseEntity<?> iniciar_sesion(@RequestBody LoginDTO loginCredentials) {
        return authService.login(loginCredentials);
    }
    @PostMapping("/register")
    ResponseEntity<?> registrarse(@RequestBody User userCredentiales) {
        return authService.register(userCredentiales);
    }
}