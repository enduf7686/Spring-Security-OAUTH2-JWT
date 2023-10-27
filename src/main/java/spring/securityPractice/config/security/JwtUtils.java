package spring.securityPractice.config.security;

import static spring.securityPractice.config.security.JwtConstants.SECRET_KEY;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import java.sql.Date;
import org.springframework.security.core.Authentication;

public class JwtUtils {

    private final static Long ACCESS_TOKEN_EXPIRED_TIME = 1000 * 60L * 30L;
    private final static Long REFRESH_TOKEN_EXPIRED_TIME = 1000 * 60L * 60L * 24L;

    public static String createAccessToken(Authentication authentication) {
        MemberDetails memberDetails = (MemberDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject("SecurityPracticeApplication")
                .claim("id", memberDetails.getId().toString())
                .claim("username", memberDetails.getUsername())
                .claim("role", memberDetails.getRole())
                .claim("providerId", memberDetails.getProviderId())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRED_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public static String createRefreshToken() {
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject("SecurityPracticeApplication")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRED_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public static MemberDetails createMemberDetails(String accessToken, String refreshToken) {
        Jws<Claims> claimsJws = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(accessToken);

        Long id = Long.valueOf(claimsJws.getBody().get("id").toString());
        String username = claimsJws.getBody().get("username").toString();
        String role = claimsJws.getBody().get("role").toString();
        String providerId = claimsJws.getBody().get("providerId").toString();

        return new MemberDetails(id, username, role, providerId);
    }
}
