package org.nvkhuy.twofactorauth.rest;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;

/**
 * REST resource for managing Two-Factor Authentication (2FA).
 * Validates Bearer tokens, extracts client info, and checks
 * whether the requesting client has permission to manage 2FA for a user.
 */
public class TwoFactorAuthRestResource {

    private static final Logger LOG = Logger.getLogger(TwoFactorAuthRestResource.class);

    private final KeycloakSession session;

    public TwoFactorAuthRestResource(KeycloakSession session) {
        this.session = session;
    }

    @Path("manage-2fa/{user_id}")
    public User2FAResource getCompanyResource(@PathParam("user_id") final String userId) {
        UserModel user = checkPermissionsAndGetUser(userId);
        return new User2FAResource(session, user);
    }

    /**
     * Validates that the current client has permission to manage the given user’s 2FA.
     */
    private UserModel checkPermissionsAndGetUser(final String userId) {
        LOG.infof("Starting 2FA permission check for userId=%s", userId);

        RealmModel realm = session.getContext().getRealm();
        LOG.debugf("Realm resolved: %s", realm.getName());

        // Extract token
        String authHeader = session.getContext().getHttpRequest()
                .getHttpHeaders()
                .getHeaderString("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            LOG.error("Missing or malformed Authorization header");
            throw new BadRequestException("Authorization header required");
        }

        String token = authHeader.substring("Bearer ".length());
        String clientId = getClientIdFromToken(token);

        if (clientId.isEmpty()) {
            LOG.error("Failed to extract clientId from token");
            throw new BadRequestException("Invalid token");
        }
        LOG.infof("Extracted clientId from token: %s", clientId);

        // Validate client
        ClientModel client = session.clients().getClientByClientId(realm, clientId);
        if (client == null) {
            LOG.errorf("Client not found in realm=%s: clientId=%s", realm.getName(), clientId);
            throw new BadRequestException("Invalid client");
        }
        LOG.debugf("Client validated: %s (UUID=%s)", client.getClientId(), client.getId());

        // Validate user
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            LOG.errorf("Target user not found in realm=%s: userId=%s", realm.getName(), userId);
            throw new BadRequestException("Invalid user");
        }
        LOG.infof("Target user=%s (id=%s)", user.getUsername(), user.getId());

        return user;
    }

    /**
     * Safely extract the clientId (azp claim) from a JWT token.
     * Returns an empty string if the token is invalid.
     */
    public static String getClientIdFromToken(String token) {
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class);
            AccessToken accessToken = verifier.getToken();
            return accessToken.getIssuedFor(); // "azp" claim
        } catch (VerificationException | IllegalArgumentException e) {
            LOG.errorf(e, "Failed to parse token for clientId");
            return "";
        }
    }
}