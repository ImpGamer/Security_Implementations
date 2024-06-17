package com.spring.security.config;

import com.spring.security.service.validation.UserValidation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidationsConfig {

    //Se crea una instancia con anotacion @Bean, para que se ejecute inmediatamente al iniciar la aplicacion
    /*De esta manera la validacion de usuarios se encontrar "encendida" desde el inicio de la aplicacion*/
    @Bean
    public UserValidation userValidation() {
        return new UserValidation();
    }
}
