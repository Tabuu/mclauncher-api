package sk.tomsik68.mclauncher.impl.login.microsoft;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyle;
import net.minidev.json.JSONValue;
import sk.tomsik68.mclauncher.api.login.ILoginService;
import sk.tomsik68.mclauncher.api.login.IProfile;
import sk.tomsik68.mclauncher.api.login.ISession;
import sk.tomsik68.mclauncher.api.services.IServicesAvailability;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MSLoginService implements ILoginService {

    private static final String
            AUTH_TOKEN_URL = "https://login.live.com/oauth20_token.srf",
            XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate",
            XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize",
            MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox",
            MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    @Override
    public ISession login(IProfile profile) throws Exception {
        String msAccessToken = getMicrosoftAccessToken("");
        TokenPair xblToken = getXBLToken(msAccessToken);
        TokenPair xstsToken = getXSTSToken(xblToken);
        String mcAccessToken = getMinecraftAccessToken(xstsToken);

        System.out.println(mcAccessToken);

        return getMinecraftSession(mcAccessToken);
    }

    @Override
    public void logout(ISession session) throws Exception {

    }

    @Override
    public boolean isAvailable(IServicesAvailability availability) {
        return availability.isServiceAvailable("");
    }

    private String getMicrosoftAccessToken(String authCode) throws IOException {
        Map<String, Object> data = mapOf(
                "client_id", "00000000402b5328",
                "code", authCode,
                "grant_type", "authorization_code",
                "redirect_uri", "https://login.live.com/oauth20_desktop.srf",
                "scope", "service::user.auth.xboxlive.com::MBI_SSL"
        );

        JSONObject response = postFormRequest(AUTH_TOKEN_URL, data);
        System.out.println(response.toJSONString(JSONStyle.NO_COMPRESS));

        return (String) response.get("access_token");
    }

    private TokenPair getXBLToken(String accessToken) throws IOException {
        JSONObject properties = new JSONObject();
        properties.put("AuthMethod", "RPS");
        properties.put("SiteName", "user.auth.xboxlive.com");
        properties.put("RpsTicket", String.format("t=%s", accessToken));

        JSONObject json = new JSONObject();
        json.put("Properties", properties);
        json.put("RelyingParty", "http://auth.xboxlive.com");
        json.put("TokenType", "JWT");

        JSONObject response = postJsonRequest(XBL_AUTH_URL, "POST", mapOf(
                "Content-Type", "application/json",
                "Accept", "application/json",
                "x-xbl-contract-version", "1"
        ),json);
        System.out.println(response.toJSONString(JSONStyle.NO_COMPRESS));

        String token = (String) response.get("Token");

        JSONObject displayClaims = (JSONObject) response.get("DisplayClaims");
        JSONArray xui = (JSONArray) displayClaims.get("xui");
        JSONObject container = (JSONObject) xui.get(0);
        String uhs = (String) container.get("uhs");

        return new TokenPair(token, uhs);
    }

    private TokenPair getXSTSToken(TokenPair xblToken) throws IOException {
        JSONObject properties = new JSONObject();
        properties.put("SandboxId", "RETAIL");
        properties.put("UserTokens", new String[] { xblToken.getToken() });

        JSONObject json = new JSONObject();
        json.put("Properties", properties);
        json.put("RelyingParty", "rp://api.minecraftservices.com/");
        json.put("TokenType", "JWT");

        System.out.println("EYYYY " + json.toJSONString(JSONStyle.NO_COMPRESS));

        JSONObject response = postJsonRequest(XSTS_AUTH_URL, "POST", mapOf(
                "Content-Type", "application/json",
                "Accept", "application/json",
                "x-xbl-contract-version", "1"
        ),json);
        System.out.println(response.toJSONString(JSONStyle.NO_COMPRESS));

        String token = (String) response.get("Token");

        JSONObject displayClaims = (JSONObject) response.get("DisplayClaims");
        JSONArray xui = (JSONArray) displayClaims.get("xui");
        JSONObject container = (JSONObject) xui.get(0);
        String uhs = (String) container.get("uhs");

        return new TokenPair(token, uhs);
    }

    private String getMinecraftAccessToken(TokenPair xstsToken) throws IOException {
        JSONObject json = new JSONObject();
        json.put("identityToken", String.format("XBL3.0 x=%s;%s", xstsToken.getHash(), xstsToken.getToken()));

        JSONObject response = postJsonRequest(MC_LOGIN_URL, "POST", mapOf(
                "Content-Type", "application/json",
                "Accept", "application/json"
        ),json);
        System.out.println(response.toJSONString(JSONStyle.NO_COMPRESS));

        return (String) response.get("access_token");
    }

    private ISession getMinecraftSession(String minecraftAccessToken) throws IOException {
        JSONObject response = postJsonRequest(MC_PROFILE_URL, "GET", mapOf(
                "Authorization", "Bearer " + minecraftAccessToken
        ),null);

        System.out.println(response.toJSONString(JSONStyle.NO_COMPRESS)); // 404 caused by profile not found!!

        return new MSSession(
                minecraftAccessToken,
                (String) response.get("id"),
                (String) response.get("name")
        );
    }

    private static Map<String, Object> mapOf(Object... values) {
        if (values.length % 2 != 0)
            throw new IllegalArgumentException("Values must have a key-value pair representation");

        Map<String, Object> map = new HashMap<>();

        for (int i = 0; i < values.length; i += 2)
            map.put(values[i].toString(), values[i + 1]);

        return map;
    }

    private static JSONObject postJsonRequest(String uri, String method, Map<String, Object> headers, JSONObject body) throws IOException {
        URL url = new URL(uri);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        for(Map.Entry<String, Object> entry : headers.entrySet()) {
            connection.setRequestProperty(entry.getKey(), entry.getValue().toString());
        }

        connection.setRequestMethod(method);
        connection.setDoOutput(true);

        if(body != null) {
            DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());

            outputStream.writeBytes(body.toJSONString(JSONStyle.LT_COMPRESS));
            outputStream.flush();
            outputStream.close();
        }

        int status = connection.getResponseCode();
        boolean error = status > 299;

        BufferedReader inputReader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8)
        );

        String line;
        StringBuilder content = new StringBuilder();
        while ((line = inputReader.readLine()) != null)
            content.append(line);

        inputReader.close();
        connection.disconnect();

        return (JSONObject) JSONValue.parse(content.toString());
    }

    private static JSONObject postFormRequest(String uri, Map<String, Object> parameters) throws IOException {
        URL url = new URL(uri);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());

        outputStream.writeBytes(getParameterString(parameters));
        outputStream.flush();
        outputStream.close();

        int status = connection.getResponseCode();
        boolean error = status > 299;

        BufferedReader inputReader = new BufferedReader(
                new InputStreamReader(error ? connection.getErrorStream() : connection.getInputStream())
        );

        String line;
        StringBuilder content = new StringBuilder();
        while ((line = inputReader.readLine()) != null)
            content.append(line);

        inputReader.close();
        connection.disconnect();

        return (JSONObject) JSONValue.parse(content.toString());
    }

    private static String getParameterString(Map<String, Object> parameters) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue().toString(), "UTF-8"));
            result.append("&");
        }


        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }

    private class TokenPair {
        private String token, hash;

        public TokenPair(String token, String hash) {
            this.token = token;
            this.hash = hash;
        }

        public String getToken() {
            return token;
        }

        public String getHash() {
            return hash;
        }

        @Override
        public String toString() {
            return "TokenPair{" +
                    "token='" + token + '\'' +
                    ", hash='" + hash + '\'' +
                    '}';
        }
    }
}
