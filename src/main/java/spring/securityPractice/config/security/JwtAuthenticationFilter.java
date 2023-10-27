package spring.securityPractice.config.security;

import static spring.securityPractice.config.security.JwtConstants.AUTHORIZATION_HEADER;
import static spring.securityPractice.config.security.JwtConstants.AUTHORIZATION_HEADER_PREFIX;

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
        Optional<Cookie> cookie = Arrays.stream(request.getCookies())
                .filter(c -> c.getName() == "refreshToken")
                .findFirst();

        if (authorizationHeader != null) {
            String accessToken = authorizationHeader.replace(AUTHORIZATION_HEADER_PREFIX, "");
            String refreshToken = cookie.get().getValue();

            MemberDetails memberDetails = JwtUtils.createMemberDetails(accessToken, refreshToken);
            OAuth2AuthenticationToken oAuth2AuthenticationToken = createToken(memberDetails);
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
        }

        filterChain.doFilter(request, response);
    }

    private OAuth2AuthenticationToken createToken(MemberDetails memberDetails) {
        return new OAuth2AuthenticationToken(
                memberDetails,
                memberDetails.getAuthorities(),
                memberDetails.getProviderId()
        );
    }
}
