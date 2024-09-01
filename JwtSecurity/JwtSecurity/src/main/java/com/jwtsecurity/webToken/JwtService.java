package com.jwtsecurity.webToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class JwtService {

    public static final String SECRET="3587C309A07226BF82B8F58843CBA1C61229A0B8079975964784B859010D0A9427752D6BB8A477E96EF927C22023512B33096DF6D124AE2401C400DECC06DD25";
    public static final long VALIDITY= TimeUnit.MINUTES.toMillis(30);

    public String generateToken(UserDetails userDetails){

        Map<String,String> claims=new HashMap<>();
        claims.put("iss","https://secure.genuinecoder.com");
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
                .signWith(generateKey())
                .compact();

    }

    private SecretKey generateKey(){

        byte[] decodeKey= Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodeKey);
    }

    public String extractUsername(String jwt){

        Claims claims=Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
        return claims.getSubject();
    }

    private Claims getClaims(String jwt){

         return  Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

    }

    public boolean isTokenValid(String jwt){

        Claims claims=getClaims(jwt);
        return claims.getExpiration().after(Date.from(Instant.now()));
    }

}