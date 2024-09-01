package com.jwtsecurity.controller;

import com.jwtsecurity.model.MyUser;
import com.jwtsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegisterController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/register/user")
    public MyUser registerUser(@RequestBody MyUser user){

         user.setPassword(passwordEncoder.encode(user.getPassword()));
         return userRepository.save(user);
    }


}
