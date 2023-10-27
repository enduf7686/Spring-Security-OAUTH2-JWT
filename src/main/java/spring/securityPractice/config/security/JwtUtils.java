package spring.securityPractice.config.security;

import static spring.securityPractice.config.security.JwtConstants.SECRET_KEY;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.sql.Date;
import org.springframework.security.core.Authentication;

public class JwtUtils {

    //TODO: 토큰 유효기간 설정
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
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public static String createRefreshToken() {
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject("SecurityPracticeApplication")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    //TODO: 예외 처리
    public static MemberDetails createMemberDetails(String jwt) {
        Jws<Claims> claimsJws = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(jwt);

        Long id = Long.valueOf(claimsJws.getBody().get("id").toString());
        String username = claimsJws.getBody().get("username").toString();
        String role = claimsJws.getBody().get("role").toString();
        String providerId = claimsJws.getBody().get("providerId").toString();

        return new MemberDetails(id, username, role, providerId);
    }
}
