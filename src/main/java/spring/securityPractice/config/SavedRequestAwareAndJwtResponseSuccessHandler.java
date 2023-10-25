package spring.securityPractice.config;

import com.nimbusds.jose.shaded.json.JSONObject;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Slf4j
public class SavedRequestAwareAndJwtResponseSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        clearAuthenticationAttributes(request);

        JSONObject jsonObject = getJsonObject(JwtUtils.createJwt(authentication), savedRequest.getRedirectUrl());
        responseJson(response, jsonObject);
    }

    private JSONObject getJsonObject(String jwt, String targetUrl) {
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
