package sk.tomsik68.mclauncher.impl.login.microsoft;

import sk.tomsik68.mclauncher.api.login.ESessionType;
import sk.tomsik68.mclauncher.api.login.ISession;

import java.util.List;

public class MSSession implements ISession {

    private String
            sessionId,
            uuid,
            username;

    public MSSession(String sessionId, String uuid, String username) {
        this.sessionId = sessionId;
        this.uuid = uuid;
        this.username = username;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public String getSessionID() {
        return this.sessionId;
    }

    @Override
    public String getUUID() {
        return this.uuid;
    }

    @Override
    public ESessionType getType() {
        return ESessionType.MICROSOFT;
    }

    @Override
    public List<Prop> getProperties() {
        return null;
    }
}
