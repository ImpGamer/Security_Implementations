package com.spring.security.service;

import com.spring.security.persistence.entity.User;
import com.spring.security.persistence.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @GetMapping("/getAll")
    ResponseEntity<List<User>> listarUsuarios() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}
