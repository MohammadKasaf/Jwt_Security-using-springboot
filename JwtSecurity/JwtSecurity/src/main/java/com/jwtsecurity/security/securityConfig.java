package com.jwtsecurity.security;

import com.jwtsecurity.service.UserService;
import com.jwtsecurity.webToken.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class securityConfig {

    @Autowired
    private UserService userService;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(){

        return new ProviderManager(authenticationProvider());
    }

    // Authentication
//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//        UserDetails user = User.builder()
//                .username("user")
//                .password(encoder.encode("chishti"))
//                .roles("USER") // Use uppercase for role consistency
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(encoder.encode("qadri"))
//                .roles("ADMIN") // Use uppercase for role consistency
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }


    @Bean
    public UserDetailsService userDetailsService(){

        return userService;

    }

    @Bean
    public AuthenticationProvider authenticationProvider(){

        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;

    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable()) // Disable CSRF
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/home", "/register/**", "/authenticate").permitAll() // Public endpoints
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll() // Allow Swagger access
                        .requestMatchers("/admin/**").hasRole("ADMIN") // Admin endpoints
                        .requestMatchers("/user/**").hasRole("USER") // User endpoints
                        .anyRequest().authenticated() // All other requests need authentication
                )
                .formLogin(formLogin -> formLogin.permitAll()) // Permit all for form login
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // Add JWT filter
                .build();
    }

}
