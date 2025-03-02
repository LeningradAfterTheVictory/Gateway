package org.example.Gateway.Gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class JwtUtil {
    @Value("${base.publickey}")
    private String publicKeyPem;

    private PublicKey publicKey;

    public JwtUtil() {}

    @PostConstruct
    public void init() {
        try {
            if (publicKeyPem == null || publicKeyPem.isBlank()) {
                throw new RuntimeException("Public key is missing or empty");
            }
            System.out.println("Public Key Loaded: " + publicKeyPem);
            this.publicKey = loadPublicKey(publicKeyPem);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    public void validateToken(final String token) {
        Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getRoles(String token) {
        Claims claims = extractAllClaims(token);
        return (String) claims.get("role");
    }

    private PublicKey loadPublicKey(String publicKeyPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyContent = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}