package com.juliamartyn.security.jwt;

import com.juliamartyn.security.services.UserPrinciple;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class JwtAuthProvider {

    @Value("${JWT_SECRET}")
    private String jwtSecret;

    public String generateJwtToken(Authentication authentication) {

        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + TimeUnit.MINUTES.toMillis(15)))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(Optional<String> token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(String.valueOf(token))
                .getBody().getSubject();
    }
}