package sk.tomsik68.mclauncher.impl.login.yggdrasil;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.UUID;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyle;
import net.minidev.json.JSONValue;
import sk.tomsik68.mclauncher.api.common.MCLauncherAPI;
import sk.tomsik68.mclauncher.api.json.IJSONSerializable;
import sk.tomsik68.mclauncher.api.login.ILoginService;
import sk.tomsik68.mclauncher.api.login.IProfile;
import sk.tomsik68.mclauncher.api.login.ISession;
import sk.tomsik68.mclauncher.api.login.LoginException;
import sk.tomsik68.mclauncher.api.services.IServicesAvailability;
import sk.tomsik68.mclauncher.impl.login.legacy.LegacyProfile;
import sk.tomsik68.mclauncher.util.FileUtils;
import sk.tomsik68.mclauncher.util.HttpUtils;

public final class YDLoginService implements ILoginService {
    public static UUID clientToken = UUID.randomUUID();
    private static String PASSWORD_LOGIN_URL = "https://authserver.mojang.com/authenticate";
    private static String SESSION_LOGIN_URL = "https://authserver.mojang.com/refresh";
    private static String SESSION_LOGOUT_URL = "https://authserver.mojang.com/invalidate";

    public YDLoginService() {
    }
    
    /**
     * Constructor for debug/custom auth url.
     * If argument is null, use default value
     *
     * @param passwordLoginUrl url for pass login and password
     * @param sessionLoginUrl url for login by session (or refresh)
     * @param sessionLogoutUrl url for logout by session
     */
    public YDLoginService(@Nullable String passwordLoginUrl,
                          @Nullable String sessionLoginUrl,
                          @Nullable String sessionLogoutUrl) {
        if (passwordLoginUrl != null) {
            PASSWORD_LOGIN_URL = passwordLoginUrl;
        }
        if (sessionLoginUrl != null) {
            SESSION_LOGIN_URL = sessionLoginUrl;
        }
        if (sessionLogoutUrl != null) {
            SESSION_LOGOUT_URL = sessionLogoutUrl;
        }
    }

    @Override
    public ISession login(IProfile profile) throws YDServiceAuthenticationException {
        MCLauncherAPI.log.fine("Logging in using yggdrassil...");
        YDLoginResponse response;
        if (profile instanceof LegacyProfile) {
            response = doPasswordLogin(profile);
        }
        else if(profile instanceof YDAuthProfile) {
            response = doSessionLogin(profile);

        } else {
            throw new IllegalArgumentException("YDLoginService can't deal with custom profile class: " + profile.getClass().getName());

        }

        MCLauncherAPI.log.fine("Login successful. Updating profile...");
        YDSession result = new YDSession(response);
        if(profile instanceof YDAuthProfile)
            ((YDAuthProfile)profile).update(result);
        return result;
    }

    public IProfile createProfile(ISession session){
        if(!(session instanceof YDSession)){
            throw new IllegalArgumentException("Profile can only be created from an YDSession. Please use YDLoginService to log in.");
        }
        return new YDAuthProfile((YDSession) session);
    }

    private String doLoginPost(String url, IJSONSerializable request) throws YDServiceAuthenticationException {
        String response = null;
        try {
            // Automatically Throws YDServiceAuthenticationException but will check for IOException and convert
            response = HttpUtils.doJSONAuthenticationPost(url, request);
            return response;
        } catch (IOException e) {
            throw new YDServiceAuthenticationException("Failed to authenticate using Mojang authentication service.", e);
        }
    }

    // performs a HTTP POST request and checks if response from the system is error-less
    private YDLoginResponse doCheckedLoginPost(String url, IJSONSerializable req) throws YDServiceAuthenticationException {
        String jsonString = doLoginPost(url, req);

		JSONObject jsonObject = (JSONObject)JSONValue.parse(jsonString);
        YDLoginResponse response = new YDLoginResponse(jsonObject);

        if(response.getError() != null) {
            MCLauncherAPI.log.fine("Login response error. JSON STRING: '".concat(jsonString).concat("'"));
			throw new YDServiceAuthenticationException("Authentication Failed: " + response.getMessage(),
					new LoginException("Error ".concat(response.getError()).concat(" : ").concat(response.getMessage())));

        }
        return response;
    }

    private YDLoginResponse doSessionLogin(IProfile profile) throws YDServiceAuthenticationException {
        MCLauncherAPI.log.fine("Using session ID login");
        YDSessionLoginRequest request = new YDSessionLoginRequest(profile.getPassword(), clientToken.toString());

        YDLoginResponse response = doCheckedLoginPost(SESSION_LOGIN_URL, request);

        return response;
    }

    private YDLoginResponse doPasswordLogin(IProfile profile) throws YDServiceAuthenticationException {
        MCLauncherAPI.log.fine("Using password-based login");
        YDPasswordLoginRequest request = new YDPasswordLoginRequest(profile.getName(), profile.getPassword(), clientToken.toString());

        YDLoginResponse response = doCheckedLoginPost(PASSWORD_LOGIN_URL, request);

        return response;
    }

    @Override
    public boolean isAvailable(IServicesAvailability availability) {
        return availability.isServiceAvailable("auth.mojang.com");
    }

    public void save(File mcInstance) throws Exception {
        File file = new File(mcInstance, "launcher_profiles.json");
        saveTo(file);
    }

    public void saveTo(File file) throws Exception {
        JSONObject obj = new JSONObject();
        if (file.exists()) {
            MCLauncherAPI.log.fine("The file already exists. YDLoginService won't overwrite client token.");
            FileReader fileReader = new FileReader(file);
            obj = (JSONObject) JSONValue.parse(fileReader);
            fileReader.close();
            if (obj.containsKey("clientToken"))
                return;
            file.delete();
        }
        FileUtils.createFileSafely(file);
        MCLauncherAPI.log.fine("Writing client token...");
        // file.createNewFile();
        obj.put("clientToken", clientToken.toString());
        FileWriter fw = new FileWriter(file);
        obj.writeJSONString(fw, JSONStyle.NO_COMPRESS);
        fw.flush();
        fw.close();
    }

    public void load(File mcInstance) throws Exception {
        File file = new File(mcInstance, "launcher_profiles.json");
        loadFrom(file);
    }

    public void loadFrom(File file) throws Exception {
        FileReader fileReader = new FileReader(file);
        JSONObject obj = (JSONObject) JSONValue.parse(fileReader);
        fileReader.close();
        clientToken = UUID.fromString(obj.get("clientToken").toString());
        MCLauncherAPI.log.fine("Loaded client token: " + clientToken.toString());
    }

    @Override
    public void logout(ISession session) throws Exception {
        YDLogoutRequest request = new YDLogoutRequest(session, clientToken);
        String response = doLoginPost(SESSION_LOGOUT_URL, request);
        if("".equals(response)) {
            MCLauncherAPI.log.fine("Logout successful.");
        } else {
            MCLauncherAPI.log.fine("Unknown error occured during logout(mojang yggdrassil didn't return empty string).");
        }

    }

}
