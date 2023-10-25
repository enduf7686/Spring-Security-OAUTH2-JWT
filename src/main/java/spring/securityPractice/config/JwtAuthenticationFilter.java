package spring.securityPractice.config;

import static spring.securityPractice.config.JwtConstants.AUTHORIZATION_HEADER;
import static spring.securityPractice.config.JwtConstants.AUTHORIZATION_HEADER_PREFIX;

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

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (authorizationHeader != null) {
            String jwt = authorizationHeader.replace(AUTHORIZATION_HEADER_PREFIX, "");
            MemberDetails memberDetails = JwtUtils.createMemberDetails(jwt);
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
