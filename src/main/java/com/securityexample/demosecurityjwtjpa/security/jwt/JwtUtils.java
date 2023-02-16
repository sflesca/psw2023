package com.securityexample.demosecurityjwtjpa.security.jwt;

import java.security.SignatureException;
import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.securityexample.demosecurityjwtjpa.security.services.UserDetailsImpl;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${my.app.jwtSecret}")
    private String jwtSecret;

    @Value("${my.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    private Algorithm algorithm;

    private JWTVerifier verifier;

    @PostConstruct
    public void init(){
        algorithm = Algorithm.HMAC256(jwtSecret);
        verifier = JWT.require(algorithm).withIssuer("Sergio Flesca").build();
    }
    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return JWT.create()
                .withIssuer("Sergio Flesca")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date((new Date()).getTime() + jwtExpirationMs))
                .withSubject("Autentication")
                .withClaim("userId", userPrincipal.getUsername())
                .withJWTId(UUID.randomUUID().toString())
                .sign(algorithm);

    }

    public String getUserNameFromJwtToken(String token) {
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT.getClaim("userId").asString();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            DecodedJWT decodedJWT = verifier.verify(authToken);
            if (!(decodedJWT.getExpiresAt().after(new Date())))
                return false;
            return true;
        } catch (JWTVerificationException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        }
        return false;
    }
}
