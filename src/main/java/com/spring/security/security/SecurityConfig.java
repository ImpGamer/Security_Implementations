package com.spring.security.security;

import com.spring.security.service.JWTUtilityService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {
    @Autowired
    private JWTUtilityService jwtutilityService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authRequest ->
                        //Rutas las cuales podra acceder cualquier usuario sin necesidad de un JWT
                        authRequest.requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement(sessionManager ->
                        sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtAuthorizationFilter(jwtutilityService),UsernamePasswordAuthenticationFilter.class)
                //Cuando intentamos acceder a una ruta protegida pero no tenemos autenticacion, nos retornara un codigo 401
                        .exceptionHandling(exceptionHandling ->
                                exceptionHandling.authenticationEntryPoint((request, response, authException) ->
                                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Acceso denegado"))
                                        ).build();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
