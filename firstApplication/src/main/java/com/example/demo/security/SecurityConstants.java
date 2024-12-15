package com.example.demo.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import io.jsonwebtoken.SignatureAlgorithm;

public class SecurityConstants {
    public static final long EXPIRATION_TIME = 864000000; // 10 Days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/users";
    
    // 512-bit key for HS512 (make sure this is at least 512 bits)
    public static final String TOKEN_SECRET = "a1b2c3d4e5f6g7h8i9j0klmnopqrstuabcdefghijklmnoa1b2c3d4e5f6g7h8i9j0klmnopqrstuabcdefghijklmno"; // 512-bit key
    
    // Correct way to create a SecretKey for HS512
    public static final SecretKey SECRET_KEY = new SecretKeySpec(TOKEN_SECRET.getBytes(), SignatureAlgorithm.HS512.getJcaName());
}
