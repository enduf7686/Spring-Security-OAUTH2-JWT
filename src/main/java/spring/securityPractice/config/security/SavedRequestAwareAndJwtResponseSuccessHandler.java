package spring.securityPractice.config.security;

import com.nimbusds.jose.shaded.json.JSONObject;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Slf4j
public class SavedRequestAwareAndJwtResponseSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new CookieRequestCache();
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String accessToken = JwtUtils.createAccessToken(authentication);
        String refreshToken = JwtUtils.createRefreshToken();

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        responseJson(response, createJson(accessToken, refreshToken, savedRequest));
    }

    private JSONObject createJson(String accessToken, String refreshToken, SavedRequest savedRequest) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField("accessToken", accessToken);
        jsonObject.appendField("refreshToken", refreshToken);
        if (savedRequest == null) {
            jsonObject.appendField("redirectUrl", "/");
        } else {
            jsonObject.appendField("redirectUrl", savedRequest.getRedirectUrl());
        }
        return jsonObject;
    }

    private void responseJson(HttpServletResponse response, JSONObject jsonObject) throws IOException {
        response.setStatus(HttpStatus.FOUND.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

        PrintWriter writer = response.getWriter();
        writer.write(jsonObject.toJSONString());
        writer.close();
    }
}
