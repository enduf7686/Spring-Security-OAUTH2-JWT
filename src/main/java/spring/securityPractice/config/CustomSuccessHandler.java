package spring.securityPractice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.LocalDateTime;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;
import spring.securityPractice.config.oauth.MemberDetails;
import spring.securityPractice.domain.Member;
import spring.securityPractice.repository.MemberRepository;

@Slf4j
public class CustomSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

//        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
//        if (savedRequest == null) {
//            super.onAuthenticationSuccess(request, response, authentication);
//            return;
//        }
//
//        clearAuthenticationAttributes(request);
//
//        String targetUrl = savedRequest.getRedirectUrl();

        MemberDetails memberDetails = (MemberDetails) authentication;

        String jwt = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject("SecurityPracticeApplication")
                .claim("id", memberDetails.getId())
                .claim("username", memberDetails.getUsername())
                .claim("role", memberDetails.getRole())
                .claim("providerId", memberDetails.getProviderId())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, "fjdifjdifjojsidfjsdofjsdi")
                .compact();

        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField("accessToken", jwt);

        response.setStatus(HttpStatus.ACCEPTED.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

        PrintWriter writer = response.getWriter();
        writer.write(jsonObject.toJSONString());
        writer.close();
    }
}
