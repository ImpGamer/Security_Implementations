package com.spring.security.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;

/*Clase donde crearemos y validaremos cada peticion de un JWT*/
@Service
@Slf4j
public class JWTUtilityService {
    @Value("classpath:jwtKeys/private_key.pem")
    private Resource PRIVATE_KEY_PATH;
    @Value("classpath:jwtKeys/public_key.pem")
    private Resource PUBLIC_KEY_PATH;
    public String generateJWT(Long userID) {
        //Obtencion de la llave privada
        PrivateKey private_key = loadPrivateKey(PRIVATE_KEY_PATH);

        /*En caso que obtengamos la llave privada crear un firmador en caso contrario marcarlo como nulo*/
        JWSSigner signer = private_key!=null?new RSASSASigner(private_key):null;
        //Fecha de creacion del token
        ZonedDateTime horaInicio = ZonedDateTime.now();
        //Conversion a formato UNIX la hora de inicio y expiracion
        long fechaInicio = horaInicio.toInstant().getEpochSecond();
        long fechaExpiracion = fechaInicio+3600;

        //Creacion de los claims (parametros) del JWT
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userID.toString())
                    .issueTime(new Date(fechaInicio * 1000))
                    .expirationTime(new Date(fechaExpiracion * 1000))
                    //Aqui claramente se colocaria el rol de cada usuario
                    .claim("Rol","User")
                    .build();

            //Indicarle al firmante los parametros del JWT y algoritmo de codificacion del JWT
        SignedJWT signJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),claimsSet);
        try {
            //Firma y construccion completa del JWT
            signJWT.sign(signer);

            //Retornamos el JWT
            return signJWT.serialize();
        }catch (JOSEException ex) {
            log.error(ex.getMessage());
            log.error("Error al tratar de firmar el JWT");
        }
        return "";
    }
    public JWTClaimsSet parseJWT(String token) {
        PublicKey publicKey = loadPublicKey(PUBLIC_KEY_PATH);

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

            //Caso que el token no se a verificado
            if(!signedJWT.verify(verifier)) {
                throw new JOSEException("Firma incorrecta del JWT");
            }
            //Obtencion de los parametros del JWT
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if(isExpirated(token)) {
                throw new JOSEException("El Token ya se encuentra expirado");
            }

            return claimsSet;
        } catch (Exception e) {
            log.error(e.getMessage());
            return null;
        }
    }

    public boolean isExpirated(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            //Si la fecha generada (actual) es posterior a la fecha de expiracion retornara un true
            return claims.getExpirationTime().before(new Date());

        }catch (Exception ex) {
            ex.printStackTrace();
            log.error(ex.getMessage());
        }
        return true;
    }
    public boolean isAdmin(String token) {
        try {
            //Decodificar el token para extraer datos
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            //Verificar si el usuario es administrador
            return claims.getClaim("Rol").toString().equalsIgnoreCase("admin");

        }catch (Exception ex) {
            log.error(ex.getMessage());
        }
        return false;
    }

    private PrivateKey loadPrivateKey(Resource resource) {
        try {
            //Leemos el arreglo de bytes del archivo que contiene la llave privada
            byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
            /*Convertimos dicho arreglo de bytes a un String con codificacion estandar UTF-8,
            * ademas de que remplazamos los valores no deseados por cadenas vacias*/
            String privateKeyPem = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----","")
                    .replace("-----END PRIVATE KEY-----","")
                    .replaceAll("\\s","");

            byte[] decodeKey = Base64.getDecoder().decode(privateKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey));

        }catch (IOException ex) {
            log.error(ex.getMessage());
            log.error("Error al leer el archivo que contiene la llave de seguridad");
        }catch (NoSuchAlgorithmException ex) {
            log.error(ex.getMessage());
            log.error("Error al tratar de convertir-codificar la llave privada");
        }catch (InvalidKeySpecException ex) {
            log.error(ex.getMessage());
            log.error("Error al generar la llave privada");
        }

        return null;
    }

    private PublicKey loadPublicKey(Resource resource) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
            String privateKeyPem = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PUBLIC KEY-----","")
                    .replace("-----END PUBLIC KEY-----","")
                    .replaceAll("\\s","");

            byte[] decodeKey = Base64.getDecoder().decode(privateKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));
        }catch (Exception ex) {
            log.error(ex.getMessage());
        }
        return null;
    }

}
