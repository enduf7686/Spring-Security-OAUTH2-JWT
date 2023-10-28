package spring.securityPractice.config.security;

import static spring.securityPractice.config.security.JwtConstants.AUTHORIZATION_HEADER;
import static spring.securityPractice.config.security.JwtConstants.AUTHORIZATION_HEADER_PREFIX;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    //TODO: 예외 처리
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
        Optional<Cookie> cookie = getCookie(request);

        if (authorizationHeader != null) {
            String accessToken = authorizationHeader.replace(AUTHORIZATION_HEADER_PREFIX, "");
            String refreshToken = cookie.get().getValue();

            try {
                MemberDetails memberDetails = JwtUtils.createMemberDetails(accessToken);
                OAuth2AuthenticationToken oAuth2AuthenticationToken = createToken(memberDetails);
                SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            } catch (ExpiredJwtException | MalformedJwtException | SignatureException e) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    private Optional<Cookie> getCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        return Arrays.stream(cookies)
                .filter(c -> c.getName().equals("refreshToken"))
                .findFirst();
    }

    private OAuth2AuthenticationToken createToken(MemberDetails memberDetails) {
        return new OAuth2AuthenticationToken(
                memberDetails,
                memberDetails.getAuthorities(),
                memberDetails.getProviderId()
        );
    }
}
