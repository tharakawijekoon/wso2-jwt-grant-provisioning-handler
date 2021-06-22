package org.wso2.custom.jwt.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.jwt.JWTBearerGrantHandler;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.custom.jwt.grant.util.BearerUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JWTBearerProvisioningHandler extends JWTBearerGrantHandler {

    private static Log log = LogFactory.getLog(JWTBearerProvisioningHandler.class);

    private String tenantDomain;

    protected void handleCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> customClaims,
                                      IdentityProvider identityProvider) throws IdentityOAuth2Exception {
        tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        super.handleCustomClaims(tokReqMsgCtx, customClaims, identityProvider);
        handleJitProvisioning(tokReqMsgCtx, identityProvider, customClaims);
    }

    private void handleJitProvisioning(OAuthTokenReqMessageContext tokReqMsgCtx, IdentityProvider identityProvider,
                                       Map<String, Object> customClaims) throws IdentityOAuth2Exception {
        ExternalIdPConfig externalIdPConfig = BearerUtil.getExternalIdpConfig(identityProvider.
                getIdentityProviderName(), tenantDomain);

        if (externalIdPConfig != null && externalIdPConfig.isProvisioningEnabled()) {

            if (log.isDebugEnabled()) {
                log.debug("JWT Bearer custom JIT provisioning flow initiated.");
            }
            AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
            String subject = user.getAuthenticatedSubjectIdentifier();
            ServiceProvider serviceProvider = BearerUtil.getServiceProvider(tokReqMsgCtx);
            Map<String, String> customClaimMap = BearerUtil.getClaims(customClaims);
            List<String> mappedRoles = BearerUtil.getMappedUserRoles(externalIdPConfig, tenantDomain, user);
            Map<String, String> localClaimValues = BearerUtil.getLocalMappedUnfilteredClaims(externalIdPConfig,
                    tenantDomain, customClaimMap);
            if (localClaimValues == null || localClaimValues.size() == 0) {
                Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
                localClaimValues = FrameworkUtils.getClaimMappings(userAttributes, false);
            }

            if (localClaimValues == null) {
                localClaimValues = new HashMap<>();
            }
            String associatedLocalUser = BearerUtil.getLocalUserAssociatedForFederatedIdentifier(
                    identityProvider.getIdentityProviderName(), subject);

            String username;
            String userIdClaimUriInLocalDialect = BearerUtil.getUserIdClaimUriInLocalDialect(externalIdPConfig);
            if (log.isDebugEnabled()) {
                log.debug("userId Claim Uri In Local Dialect : " + userIdClaimUriInLocalDialect);
            }
            if (BearerUtil.isUserNameFoundFromUserIDClaimURI(localClaimValues, userIdClaimUriInLocalDialect)) {
                username = localClaimValues.get(userIdClaimUriInLocalDialect);
                if (log.isDebugEnabled()) {
                    log.debug("UserName Found From UserID Claim URI : " + username);
                }
            } else {
                username = associatedLocalUser;
                if (log.isDebugEnabled()) {
                    log.debug("UserName not Found From UserID Claim URI, username : " + username);
                }
            }

            if (StringUtils.isEmpty(username)) {
                username = subject;
                if (log.isDebugEnabled()) {
                    log.debug("UserName is Empty hence defaulting to SubjectIdentifier, username : " + username);
                }
            }
            localClaimValues.put(FrameworkConstants.ASSOCIATED_ID, subject);
            localClaimValues.put(FrameworkConstants.IDP_ID, identityProvider.getIdentityProviderName());
            if (log.isDebugEnabled()) {
                log.debug("Adding " + FrameworkConstants.ASSOCIATED_ID + " : " + subject + " and "
                        + FrameworkConstants.IDP_ID + " : " + identityProvider.getIdentityProviderName()
                        + " to local claim values.");
            }
            // Remove role claim from local claims as roles are specifically handled.
            localClaimValues.remove(FrameworkUtils.getLocalClaimUriMappedForIdPRoleClaim(externalIdPConfig));
            BearerUtil.handleProvisioning(username, mappedRoles, localClaimValues, tenantDomain,
                    serviceProvider.getApplicationName(), externalIdPConfig);

            /*
            If AlwaysSendMappedLocalSubjectId is selected, need to get the local user associated with the
            federated idp.
            */
            String associatedLocalUserName = null;
            if (serviceProvider.getClaimConfig().isAlwaysSendMappedLocalSubjectId()) {
                associatedLocalUserName = BearerUtil.getLocalUserAssociatedForFederatedIdentifier(
                        identityProvider.getIdentityProviderName(), subject);
                if (log.isDebugEnabled()) {
                    log.debug("Assert identity using mapped local subject identifier is selected.");
                }
            }
            if (StringUtils.isNotEmpty(associatedLocalUserName)) {
                if (log.isDebugEnabled()) {
                    log.debug("AlwaysSendMappedLocalSubjectID is selected in service provider level, "
                            + "equivalent local user : " + associatedLocalUserName);
                }
                setAssociatedLocalUserToTokenReqMessageContext(tokReqMsgCtx, associatedLocalUserName, serviceProvider);
            }
        }
    }

    private void setAssociatedLocalUserToTokenReqMessageContext(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                                     String associatedLocalUserName,
                                                                     ServiceProvider serviceProvider) {
        String fullQualifiedAssociatedUserId = FrameworkUtils.prependUserStoreDomainToName(
                associatedLocalUserName + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain);
        UserCoreUtil.setDomainInThreadLocal(UserCoreUtil.extractDomainFromName(associatedLocalUserName));
        AuthenticatedUser authenticatedUser = OAuth2Util.getUserFromUserName(fullQualifiedAssociatedUserId);
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedUser.getUserName(), serviceProvider);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
    }

}
