package com.jwtsecurity.service;

import com.jwtsecurity.model.MyUser;
import com.jwtsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public  UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{

        Optional<MyUser> user=userRepository.findByUsername(username);
        if(user.isPresent()){

            var userObj=user.get();
            return User.builder().username(userObj.getUsername())
                    .password(userObj.getPassword())
                    .roles(userObj.getRole())
                    .build();
        }
        else{

             throw new UsernameNotFoundException(username);
        }
    }

}
