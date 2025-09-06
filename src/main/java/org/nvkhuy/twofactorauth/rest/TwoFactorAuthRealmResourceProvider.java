package org.nvkhuy.twofactorauth.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class TwoFactorAuthRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public TwoFactorAuthRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new TwoFactorAuthRestResource(session);
    }

    @Override
    public void close() {
    }

}
