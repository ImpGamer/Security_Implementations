package com.spring.security.service;

import com.spring.security.models.dtos.LoginDTO;
import com.spring.security.models.dtos.ResponseDTO;
import com.spring.security.persistence.entity.User;
import com.spring.security.persistence.repository.UserRepository;
import com.spring.security.service.validation.UserValidation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUtilityService jwtUtilityService;
    @Autowired
    private UserValidation userValidation;

    public ResponseEntity<?> login(LoginDTO login) {
        String token;

        try {
            Optional<User> userBD = userRepository.findUserByEmail(login.getEmail());
            if(userBD.isEmpty()) {return new ResponseEntity<>("Usuario no registrado", HttpStatus.BAD_REQUEST);}

            if(verifyPassword(login.getPassword(),userBD.get().getPassword())) {
                token = jwtUtilityService.generateJWT(userBD.get().getId());
            } else {
                return new ResponseEntity<>("Contraseña invalida",HttpStatus.BAD_REQUEST);
            }

            return ResponseEntity.ok("{\"token\":\""+token+"\"}");
        }catch (Exception ex) {
            log.error(ex.getMessage());
            return new ResponseEntity<>("Algo ha salido mal! Vuelve a intentarlo mas tarde",HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<?> register(User user) {
        try {
            ResponseDTO responseDTO = userValidation.validate(user);
            if(responseDTO.getNumOfErrors() > 0) {return new ResponseEntity<>(responseDTO,HttpStatus.BAD_REQUEST);}
            List<User> all_users = userRepository.findAll();

            for(User usuario: all_users) {
                if(usuario.getEmail().equals(user.getEmail())) {
                    return new ResponseEntity<>("El correo ingresado ya se encuentra registrado. Intente con otro.",HttpStatus.IM_USED);
                }
            }
            //Clase para encriptar contraseina del usuario
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            return new ResponseEntity<>(userRepository.save(user),HttpStatus.CREATED);

        }catch (Exception ex) {
            log.error(ex.getMessage());
            return new ResponseEntity<>("Algo ha salido mal! Vuelve a intentarlo mas tarde",HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private boolean verifyPassword(String inputPassword,String storedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        //Si el password ingresado por el usuario y el almacenado son iguales retornara true
        return encoder.matches(inputPassword, storedPassword);
    }
}
