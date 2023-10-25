package spring.securityPractice.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.securityPractice.config.oauth.MemberDetails;
import spring.securityPractice.config.oauth.MemberOauth2UserService;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final MemberOauth2UserService memberOauth2UserService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if (authorization != null) {
            String jwt = authorization.substring(7);
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey("fjdifjdifjojsidfjsdofjsdi")
                    .parseClaimsJws(jwt);
            String username = claimsJws.getBody().get("username").toString();
            log.info("claimsJws.getBody().get(\"username\")={}", username);
            log.info("claimsJws.getSignature()={}", claimsJws.getSignature());

            MemberDetails userDetails = memberOauth2UserService.loadUserByUsername(username);
            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(userDetails,
                    userDetails.getAuthorities(), userDetails.getRegistrationId());
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
        }

        filterChain.doFilter(request, response);
    }
}