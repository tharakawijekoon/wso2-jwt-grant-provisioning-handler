package org.wso2.custom.jwt.grant.util;

import net.minidev.json.JSONArray;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.*;
import java.util.stream.Collectors;

public class BearerUtil {
    private static Log log = LogFactory.getLog(BearerUtil.class);

    private BearerUtil() {
    }

    public static void handleProvisioning(String subjectIdentifier, List<String> mappedRoles,
                                          Map<String, String> extAttributesValueMap, String tenantDomain,
                                          String spName, ExternalIdPConfig externalIdPConfig) {
        try {
            @SuppressWarnings("unchecked")
            String userStoreDomain = null;
            String provisioningClaimUri = externalIdPConfig.getProvisioningUserStoreClaimURI();
            String provisioningUserStoreId = externalIdPConfig.getProvisioningUserStoreId();

            if (provisioningUserStoreId != null) {
                userStoreDomain = provisioningUserStoreId;
            } else if (provisioningClaimUri != null) {
                userStoreDomain = extAttributesValueMap.get(provisioningClaimUri);
            }

            // setup thread local variable to be consumed by the provisioning
            // framework.
            ThreadLocalProvisioningServiceProvider serviceProvider = new ThreadLocalProvisioningServiceProvider();
            serviceProvider.setServiceProviderName(spName);
            serviceProvider.setJustInTimeProvisioning(true);
            serviceProvider.setClaimDialect(ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT);
            serviceProvider.setTenantDomain(tenantDomain);
            IdentityApplicationManagementUtil.setThreadLocalProvisioningServiceProvider(serviceProvider);

            FrameworkUtils.getProvisioningHandler().handle(mappedRoles, subjectIdentifier,
                    extAttributesValueMap, userStoreDomain, tenantDomain);
        } catch (FrameworkException e) {
            log.error("User provisioning failed!", e);
        } finally {
            IdentityApplicationManagementUtil.resetThreadLocalProvisioningServiceProvider();
        }
    }

    public static ServiceProvider getServiceProvider(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isBlank(spTenantDomain)) {
            spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        String spName;
        ServiceProvider serviceProvider;
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            spName = applicationMgtService
                    .getServiceProviderNameByClientId(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                            "oauth2", spTenantDomain);
            serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);

        } catch (IdentityApplicationManagementException e) {
            throw new  IdentityOAuth2Exception(
                    "Exception while getting ServiceProvider, ", e);
        }
        return serviceProvider;
    }

    public static ExternalIdPConfig getExternalIdpConfig(String externalIdPConfigName, String tenantDomain)
            throws IdentityOAuth2Exception {
        ExternalIdPConfig externalIdPConfig;
        try {
            externalIdPConfig = ConfigurationFacade.getInstance()
                    .getIdPConfigByName(externalIdPConfigName, tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw new IdentityOAuth2Exception("Exception while getting IdP by name", e);
        }
        return externalIdPConfig;
    }


    public static List<String> getMappedUserRoles(ExternalIdPConfig externalIdPConfig, String tenantDomain,
                                                  AuthenticatedUser user) throws IdentityOAuth2Exception {
        boolean useDefaultIdpDialect = externalIdPConfig.useDefaultLocalIdpDialect();
        //idp is having oidc claim dialect as default
        String idPStandardDialect = "http://wso2.org/oidc/claim";
        String idpRoleClaimUri = FrameworkUtils.getIdpRoleClaimUri(externalIdPConfig);
        Map<ClaimMapping, String> extAttrs = user.getUserAttributes();
        Map<String, String> originalExternalAttributeValueMap = FrameworkUtils.getClaimMappings(
                extAttrs, false);
        Map<String, String> claimMapping = null;
        if (useDefaultIdpDialect && StringUtils.isNotBlank(idPStandardDialect)) {
            try {
                claimMapping = ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon(
                        idPStandardDialect, originalExternalAttributeValueMap.keySet(),
                        tenantDomain, true);
            } catch (ClaimMetadataException e) {
                throw new IdentityOAuth2Exception("Error while handling claim mappings", e);
            }
        }

        if (claimMapping != null) {
            //Ex. Standard dialects like OIDC.
            idpRoleClaimUri = claimMapping.get(FrameworkConstants.LOCAL_ROLE_CLAIM_URI);
        }

        /* Get the mapped user roles according to the mapping in the IDP configuration. Exclude the unmapped from the
         returned list.
         */
        List<String> identityProviderMappedUserRolesUnmappedExclusive = FrameworkUtils
                .getIdentityProvideMappedUserRoles(externalIdPConfig, originalExternalAttributeValueMap,
                        idpRoleClaimUri, true);

        return identityProviderMappedUserRolesUnmappedExclusive;
    }

    public static Map<String, String> getLocalMappedUnfilteredClaims(ExternalIdPConfig externalIdPConfig,
                                                                     String tenantDomain,
                                                                     Map<String, String> remoteClaims)
            throws IdentityOAuth2Exception {
        ClaimMapping[] idPClaimMappings = externalIdPConfig.getClaimMappings();

        if (idPClaimMappings == null) {
            idPClaimMappings = new ClaimMapping[0];
        }

        boolean useDefaultIdpDialect = externalIdPConfig.useDefaultLocalIdpDialect();

        // When null the local claim dialect will be used.
        String idPStandardDialect = null;
        if (useDefaultIdpDialect || !useLocalClaimDialectForClaimMappings()) {
            idPStandardDialect = "http://wso2.org/oidc/claim";
        }

        Map<String, String> localUnfilteredClaims = new HashMap<>();


        // claim mapping from local IDP to remote IDP : local-claim-uri / idp-claim-uri

        Map<String, String> localToIdPClaimMap = null;
        Map<String, String> defaultValuesForClaims = new HashMap<>();

        loadDefaultValuesForClaims(idPClaimMappings, defaultValuesForClaims);

        if (idPStandardDialect != null || useDefaultIdpDialect) {
            localToIdPClaimMap = getLocalToIdpClaimMappingWithStandardDialect(remoteClaims, idPClaimMappings,
                    tenantDomain, idPStandardDialect);
        } else if (idPClaimMappings.length > 0) {
            localToIdPClaimMap = FrameworkUtils.getClaimMappings(idPClaimMappings, true);
        } else {
            log.warn("Authenticator :  does not have " +
                    "a standard dialect and IdP : does not have custom claim mappings. Cannot proceed with claim mappings");
        }

        // Loop remote claims and map to local claims
        mapRemoteClaimsToLocalClaims(remoteClaims, localUnfilteredClaims, localToIdPClaimMap, defaultValuesForClaims);

        return localUnfilteredClaims;
    }

    private static boolean useLocalClaimDialectForClaimMappings() {

        return FileBasedConfigurationBuilder.getInstance().isCustomClaimMappingsForAuthenticatorsAllowed();
    }

    private static void loadDefaultValuesForClaims(ClaimMapping[] idPClaimMappings,
                                                   Map<String, String> defaultValuesForClaims) {

        defaultValuesForClaims.putAll(Arrays.asList(idPClaimMappings).stream().filter(claimMapping -> StringUtils.
                isNotBlank(claimMapping.getDefaultValue())).collect(Collectors.toMap(claimMapping -> claimMapping.
                getLocalClaim().getClaimUri(), claimMapping -> claimMapping.getDefaultValue())));
    }

    private static Map<String, String> getLocalToIdpClaimMappingWithStandardDialect(Map<String, String> remoteClaims,
                                                                                    ClaimMapping[] idPClaimMappings,
                                                                                    String tenantDomain,
                                                                                    String idPStandardDialect)
            throws IdentityOAuth2Exception {
        Map<String, String> localToIdPClaimMap;
        if (idPStandardDialect == null) {
            idPStandardDialect = ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT;
        }

        try {
            localToIdPClaimMap = getClaimMappings(idPStandardDialect,
                    remoteClaims.keySet(), tenantDomain, true);
        } catch (Exception e) {
            throw new IdentityOAuth2Exception("Error occurred while getting claim mappings for " +
                    "received remote claims from " +
                    idPStandardDialect + " dialect to " +
                    ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT + " dialect for " +
                    tenantDomain + " to handle federated claims", e);
        }
        // adding remote claims with default values also to the key set because they may not come from the federated IdP
        localToIdPClaimMap.putAll(Arrays.stream(idPClaimMappings).filter(claimMapping -> StringUtils.
                isNotBlank(claimMapping.getDefaultValue()) && !localToIdPClaimMap.containsKey(claimMapping.
                getLocalClaim().getClaimUri())).collect(Collectors.toMap(claimMapping -> claimMapping.getLocalClaim().
                getClaimUri(), ClaimMapping::getDefaultValue)));

        return localToIdPClaimMap;
    }

    /**
     * @param otherDialect
     * @param keySet
     * @param tenantDomain
     * @param useLocalDialectAsKey
     * @return
     * @throws FrameworkException
     */
    private static Map<String, String> getClaimMappings(String otherDialect, Set<String> keySet,
                                                        String tenantDomain, boolean useLocalDialectAsKey)
            throws FrameworkException {

        Map<String, String> claimMapping = null;
        try {
            claimMapping = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(otherDialect, keySet, tenantDomain,
                            useLocalDialectAsKey);
        } catch (ClaimMetadataException e) {
            throw new FrameworkException("Error while loading mappings.", e);
        }

        if (claimMapping == null) {
            claimMapping = new HashMap<>();
        }

        return claimMapping;
    }

    private static void mapRemoteClaimsToLocalClaims(Map<String, String> remoteClaims,
                                                     Map<String, String> localUnfilteredClaims,
                                                     Map<String, String> localToIdPClaimMap,
                                                     Map<String, String> defaultValuesForClaims) {
        for (Map.Entry<String, String> entry : localToIdPClaimMap.entrySet()) {
            String localClaimURI = entry.getKey();
            String claimValue = remoteClaims.get(localToIdPClaimMap.get(localClaimURI));
            if (StringUtils.isEmpty(claimValue)) {
                claimValue = defaultValuesForClaims.get(localClaimURI);
            }
            if (!StringUtils.isEmpty(claimValue)) {
                localUnfilteredClaims.put(localClaimURI, claimValue);
            }
        }
    }

    public static String getLocalUserAssociatedForFederatedIdentifier(String idpName, String authenticatedSubjectIdentifier)
            throws IdentityOAuth2Exception {

        String username;
        try {
            UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
            username = userProfileAdmin.getNameAssociatedWith(idpName, authenticatedSubjectIdentifier);
        } catch (UserProfileException e) {
            throw new IdentityOAuth2Exception (String.format(FrameworkErrorConstants.ErrorMessages.
                    ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getMessage(), idpName), e);
        }
        return username;
    }

    public static String getUserIdClaimUriInLocalDialect(ExternalIdPConfig idPConfig) {
        // get external identity provider user id claim URI.
        String userIdClaimUri = idPConfig.getUserIdClaimUri();

        if (StringUtils.isBlank(userIdClaimUri)) {
            return null;
        }

        boolean useDefaultLocalIdpDialect = idPConfig.useDefaultLocalIdpDialect();
        if (useDefaultLocalIdpDialect) {
            return userIdClaimUri;
        } else {
            ClaimMapping[] claimMappings = idPConfig.getClaimMappings();
            if (!ArrayUtils.isEmpty(claimMappings)) {
                for (ClaimMapping claimMapping : claimMappings) {
                    if (userIdClaimUri.equals(claimMapping.getRemoteClaim().getClaimUri())) {
                        return claimMapping.getLocalClaim().getClaimUri();
                    }
                }
            }
        }

        return null;
    }

    public static boolean isUserNameFoundFromUserIDClaimURI(Map<String, String> localClaimValues, String
            userIdClaimUriInLocalDialect) {

        return StringUtils.isNotBlank(userIdClaimUriInLocalDialect) && StringUtils.isNotBlank
                (localClaimValues.get(userIdClaimUriInLocalDialect));
    }

    public static Map<String, String> getClaims(Map<String, Object> customClaims) {

        Map<String, String> customClaimMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            String entryKey = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof JSONArray) {
                String multiValueSeparator = FrameworkUtils.getMultiAttributeSeparator();
                String multiValuesWithSeparator = StringUtils.join((Collection) value, multiValueSeparator);
                customClaimMap.put(entry.getKey(), multiValuesWithSeparator);
            } else {
                customClaimMap.put(entry.getKey(), value.toString());
            }

        }
        return customClaimMap;
    }

}
