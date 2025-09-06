package org.nvkhuy.twofactorauth.rest;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.utils.CredentialHelper;
import org.nvkhuy.twofactorauth.dto.TwoFactorAuthSecretData;
import org.nvkhuy.twofactorauth.dto.TwoFactorAuthSubmission;
import org.nvkhuy.twofactorauth.dto.TwoFactorAuthVerificationData;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.utils.TotpUtils;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class User2FAResource {
    private static final Logger LOG = Logger.getLogger(User2FAResource.class);

    private final KeycloakSession session;
    private final UserModel user;

    final String CODE_SUCCESS = "SUCCESS";
    final String CODE_TOTP_NOT_ENABLED = "TOTP_NOT_ENABLED";
    final String CODE_OPERATION_FAILED = "OPERATION_FAILED";
    public final int TotpSecretLength = 20;

    public User2FAResource(KeycloakSession session, UserModel user) {
        this.session = session;
        this.user = user;
    }

    @GET
    @Path("generate-2fa")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response generate2FA() {
        final RealmModel realm = this.session.getContext().getRealm();
        final String totpSecret = HmacOTP.generateSecret(TotpSecretLength);
        final String totpSecretQrCode = TotpUtils.qrCode(totpSecret, realm, user);
        final String totpSecretEncoded = Base32.encode(totpSecret.getBytes());
        return Response.ok(new TwoFactorAuthSecretData(totpSecretEncoded, totpSecretQrCode)).build();
    }

    @POST
    @NoCache
    @Path("validate-2fa-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validate2FACode(final TwoFactorAuthVerificationData submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp validation are blank");
        }

        final CredentialModel credentialModel = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .filter(c -> c.getUserLabel().equals(submission.getDeviceName()))
                .findFirst()
                .orElse(null);

        if (credentialModel == null) {
            throw new BadRequestException("device not found");
        }

        boolean isCredentialsValid;
        try {
            final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel);
            final String credentialId = otpCredentialModel.getId();
            isCredentialsValid = user.credentialManager()
                    .isValid(new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, submission.getTotpCode()));
        } catch (RuntimeException e) {
            e.printStackTrace();
            throw new InternalServerErrorException("internal error");
        }

        if (!isCredentialsValid) {
            throw new BadRequestException("invalid totp code");
        }

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("submit-2fa")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final TwoFactorAuthSubmission submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp registration are blank");
        }

        final String encodedTotpSecret = submission.getEncodedTotpSecret();
        final String totpSecret = new String(Base32.decode(encodedTotpSecret));
        if (totpSecret.length() < TotpSecretLength) {
            throw new BadRequestException("totp secret is invalid");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .filter(c -> c.getUserLabel().equals(submission.getDeviceName()))
                .findFirst()
                .orElse(null);

        if (credentialModel != null && !submission.isOverwrite()) {
            throw new ForbiddenException("2FA is already configured for device: " + submission.getDeviceName());
        }

        final OTPCredentialModel otpCredentialModel =
                OTPCredentialModel.createFromPolicy(realm, totpSecret, submission.getDeviceName());

        try {
            boolean created = CredentialHelper.createOTPCredential(
                    this.session, realm, user,
                    submission.getTotpInitialCode(),
                    otpCredentialModel
            );

            if (!created) {
                LOG.warnf("OTP registration failed: invalid initial code for user=%s, deviceName=%s",
                        user.getUsername(), submission.getDeviceName());
                throw new BadRequestException("otp registration data is invalid");
            }

            LOG.infof("OTP credential created successfully for user=%s, deviceName=%s",
                    user.getUsername(), submission.getDeviceName());

            this.user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            LOG.infof("removing CONFIGURE_TOTP for user=%s", user.getUsername());

        } catch (Exception e) {
            LOG.errorf(e, "Unexpected error while creating OTP credential for user=%s, deviceName=%s, secret=%s",
                    user.getUsername(), submission.getDeviceName(), otpCredentialModel.getSecretData());
            throw new InternalServerErrorException("Internal error while creating OTP credential");
        }


        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("disable-totp")
    @Produces(MediaType.APPLICATION_JSON)
    public Response disableTotp() {
        SubjectCredentialManager credManager = user.credentialManager();
        List<CredentialModel> totpCreds = credManager
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .collect(Collectors.toList());

        if (totpCreds.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "TOTP is not enabled for this user",
                            "code", CODE_TOTP_NOT_ENABLED
                    ))
                    .build();
        }

        try {
            for (CredentialModel cred : totpCreds) {
                boolean removed = credManager.removeStoredCredentialById(cred.getId());
                if (!removed) {
                    throw new RuntimeException("Failed to remove credential " + cred.getId());
                }
            }
        } catch (Exception e) {
            return Response.serverError()
                    .entity(Map.of(
                            "error", "Failed to disable TOTP",
                            "code", CODE_OPERATION_FAILED
                    ))
                    .build();
        }

        return Response.ok(Map.of(
                "message", "TOTP disabled successfully",
                "enabled", false,
                "userId", user.getId(),
                "code", CODE_SUCCESS
        )).build();
    }
}