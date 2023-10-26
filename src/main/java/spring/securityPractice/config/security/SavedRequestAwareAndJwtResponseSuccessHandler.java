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

    //TODO: refreshToken 발급 기능 구현하기
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        JSONObject json;
        if (savedRequest == null) {
            json = createJson(JwtUtils.createJwt(authentication), "/");
        } else {
            json = createJson(JwtUtils.createJwt(authentication), savedRequest.getRedirectUrl());
        }
        responseJson(response, json);
    }

    private JSONObject createJson(String jwt, String targetUrl) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField("accessToken", jwt);
        jsonObject.appendField("redirectUrl", targetUrl);
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
