package com.spring.security.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.spring.security.service.JWTUtilityService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Service
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Autowired
    private JWTUtilityService jwtUtilityService;

    public JwtAuthorizationFilter(JWTUtilityService jwtutilityService) {
        this.jwtUtilityService = jwtutilityService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        //Confirmamos que el header extraido (donde ira el JWT) no se encuentre vacio o no sea de tipo "Bearer Token"
        if(header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request,response);
            return;
        }
        //Recortaremos los primeros siete caracteres para no extraer el "Bearer "
        String token = header.substring(7);
        try {
            //Validamos el token y extraemos los atributos
            JWTClaimsSet claims = jwtUtilityService.parseJWT(token);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(claims.getSubject(),null,
                    Collections.emptyList());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        }catch (Exception ex) {
            log.error(ex.getMessage());
        }
        filterChain.doFilter(request,response);
    }
}
