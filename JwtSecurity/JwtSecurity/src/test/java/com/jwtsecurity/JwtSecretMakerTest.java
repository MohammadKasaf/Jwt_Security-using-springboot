package com.jwtsecurity;

import io.jsonwebtoken.security.Keys;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;


public class JwtSecretMakerTest {

    @Test
    public void generateSecretKey() {
        // Generating a secret key using HS512 algorithm via Jwts
        SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);

        // Converting the secret key to a hexadecimal string
        String encodedKey = DatatypeConverter.printHexBinary(key.getEncoded());

        // Printing the encoded secret key
        System.out.println("Encoded secret key: " + encodedKey);
    }
}
