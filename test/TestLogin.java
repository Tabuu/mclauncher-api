import static org.junit.Assert.*;

import org.junit.Test;

import sk.tomsik68.mclauncher.api.login.ISession;
import sk.tomsik68.mclauncher.impl.login.MinecraftProfile;
import sk.tomsik68.mclauncher.impl.login.legacy.LegacyLoginService;


public class TestLogin {

    @Test
    public void test() {
        MinecraftProfile profile = new MinecraftProfile("Tomsik68@gmail.com", "mypassword");
        LegacyLoginService lls = new LegacyLoginService();
        try {
            ISession session = lls.login(profile);
            System.out.println(session.getSessionID());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
