package com.spring.security.service.validation;

import com.spring.security.models.dtos.ResponseDTO;
import com.spring.security.persistence.entity.User;

public class UserValidation {

    public ResponseDTO validate(User usuario) {
        ResponseDTO respuesta = new ResponseDTO();

        respuesta.setNumOfErrors(0);
        if(usuario.getName().isBlank() || usuario.getName().isEmpty()
        || usuario.getPassword().isBlank() || usuario.getPassword().isEmpty() || usuario.getPassword().length() < 8)  {
            respuesta.setNumOfErrors(respuesta.getNumOfErrors()+1);
            respuesta.setMessage("Nombre o contraseñas no pueden ser vacios");
        }
        if(!usuario.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            respuesta.setNumOfErrors(respuesta.getNumOfErrors()+1);
            respuesta.setMessage("El correo no es valido.");
        } else if(!usuario.getPassword().matches("^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,16}$")) {
            respuesta.setNumOfErrors(respuesta.getNumOfErrors()+1);
            respuesta.setMessage("La contraseña debe tener entre 8 y 16 caracteres, al menos un número, una minuscula y una mayuscula");
        }
        return respuesta;
    }
}
