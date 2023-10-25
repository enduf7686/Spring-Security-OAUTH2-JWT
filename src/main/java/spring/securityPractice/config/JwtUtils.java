package spring.securityPractice.config;

import static spring.securityPractice.config.JwtConstants.SECRET_KEY;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.sql.Date;
import org.springframework.security.core.Authentication;
import spring.securityPractice.config.oauth.MemberDetails;

public class JwtUtils {

    public static String createJwt(Authentication authentication) {
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
