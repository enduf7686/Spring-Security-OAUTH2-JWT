package spring.securityPractice.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtConstants {

    public static String SECRET_KEY;

    @Value("${jwt.secretKey}")
    public void setSecretKey(String secretKey) {
        SECRET_KEY = secretKey;
    }

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";
}
