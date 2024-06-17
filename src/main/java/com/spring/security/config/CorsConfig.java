package com.spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        //Todas las rutas privadas que tendran permiso de cors (todas las rutas "endpoints" del proyecto)
        registry.addMapping("/**")
                //URL del frontend o URL permitida para hacer peticiones a nuestra API
                .allowedOrigins("http://localhost:2020")
                //Metodos HTTP que puede realizar esta URL
                .allowedMethods("GET","POST","PUT","PATCH","DELETE")
                .allowedHeaders("Origin","Content-Type","Accept","Authorization")
                .allowCredentials(true)
                .maxAge(3600);

        registry.addMapping("/auth/**")
                .allowedOrigins("http://localhost:2020")
                .allowedMethods("GET","POST","PUT","PATCH","DELETE")
                .allowedHeaders("Origin","Content-Type","Accept","Authorization")
                .allowCredentials(false)
                .maxAge(3600);
    }
}
