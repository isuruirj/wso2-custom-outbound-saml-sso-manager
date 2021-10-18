package org.wso2.carbon.identity.custom.samlsso.manager;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class AuthContextSAMLSSOManager extends DefaultSAML2SSOManager {

    private static Log log = LogFactory.getLog(AuthContextSAMLSSOManager.class);

    private static final String SIGN_AUTH2_SAML_USING_SUPER_TENANT = "SignAuth2SAMLUsingSuperTenant";
    private static final String NAME_ID_TYPE = "NameIDType";
    private static final String SAML_SSO_IDPS = "SAMLSSOIdps";
    private static final String SAML_SSO_DEFAULT_AUTHN_CLASSES = "SAMLSSODefaultAuthnContextClasses";
    private IdentityProvider identityProvider = null;
    private Map<String, String> properties;
    private String tenantDomain;

    @Override
    public void init(String tenantDomain, Map<String, String> properties, IdentityProvider idp)
            throws SAMLSSOException {

        super.init(tenantDomain, properties, idp);
        this.tenantDomain = tenantDomain;
        this.identityProvider = idp;
        this.properties = properties;
    }

    @Override
    protected AuthnRequest buildAuthnRequest(HttpServletRequest request, boolean isPassive, String idpUrl,
                                             AuthenticationContext context) throws SAMLSSOException {

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                        .get(SSOConstants.AUTHENTICATOR_NAME);

        List<String> idps = null;
        if (authenticatorConfig != null) {
            String applicableIdps = authenticatorConfig.getParameterMap().get(SAML_SSO_IDPS);
            idps = Arrays.asList(applicableIdps.split("\\s*,\\s*"));
        }

        if (idps != null && !idps.isEmpty() && idps.contains(identityProvider.getIdentityProviderName())) {
            IssuerBuilder issuerBuilder = new IssuerBuilder();
            Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");

            String spEntityId = getIssuer(context);

            if (spEntityId != null && !spEntityId.isEmpty()) {
                issuer.setValue(spEntityId);
            } else {
                issuer.setValue("carbonServer");
            }

            DateTime issueInstant = new DateTime();

            /* Creation of AuthRequestObject */
            AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
            AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                    "AuthnRequest", "samlp");
            authRequest.setForceAuthn(isForceAuthenticate(context));
            authRequest.setIsPassive(isPassive);
            authRequest.setIssueInstant(issueInstant);

            String includeProtocolBindingProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
            if (StringUtils.isEmpty(includeProtocolBindingProp) || Boolean.parseBoolean(includeProtocolBindingProp)) {
                authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            }

            String acsUrl = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.ACS_URL);

            if (StringUtils.isNotEmpty(acsUrl) && log.isDebugEnabled()) {
                log.debug("Picking SAML acs URL from " + identityProvider.getIdentityProviderName() + " IDP's "
                        + "configuration: " + acsUrl);
            }

            if (StringUtils.isEmpty(acsUrl) && authenticatorConfig != null) {
                String tmpAcsUrl = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.SAML_SSO_ACS_URL);
                if (StringUtils.isNotBlank(tmpAcsUrl)) {
                    acsUrl = tmpAcsUrl;
                    if (log.isDebugEnabled()) {
                        log.debug("Picking SAML acs URL from application-authentication.xml: " + acsUrl);
                    }
                }
            }

            if (StringUtils.isEmpty(acsUrl)) {
                acsUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
                if (log.isDebugEnabled()) {
                    log.debug("Falling back to default SAML acs URL of the server: " + acsUrl);
                }
            }

            authRequest.setAssertionConsumerServiceURL(acsUrl);
            authRequest.setIssuer(issuer);
            authRequest.setID(SSOUtils.createID());
            authRequest.setVersion(SAMLVersion.VERSION_20);
            authRequest.setDestination(idpUrl);

            String attributeConsumingServiceIndexProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
            if (StringUtils.isNotEmpty(attributeConsumingServiceIndexProp)) {
                try {
                    authRequest.setAttributeConsumingServiceIndex(Integer
                            .valueOf(attributeConsumingServiceIndexProp));
                } catch (NumberFormatException e) {
                    log.error(
                            "Error while populating SAMLRequest with AttributeConsumingServiceIndex: "
                                    + attributeConsumingServiceIndexProp, e);
                }
            }

            String includeNameIDPolicyProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);

            boolean isNameIDPolicyPropIncluded;
            if (Boolean.parseBoolean(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.IGNORE_NAME_ID_POLICY_IF_UNSPECIFIED))) {
                // Ignores name ID policy if not specified in the configuration.
                isNameIDPolicyPropIncluded = Boolean.parseBoolean(includeNameIDPolicyProp);
            } else {
                // Empty string check retained for backward compatibility.
                isNameIDPolicyPropIncluded = StringUtils.isEmpty(includeNameIDPolicyProp) ||
                        Boolean.parseBoolean(includeNameIDPolicyProp);
            }

            if (isNameIDPolicyPropIncluded) {
                NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
                NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();

                String nameIdType = properties.get(NAME_ID_TYPE);
                if (StringUtils.isBlank(nameIdType)) {
                    // NameID format was not set from the UI. Check the application-authentication.xml configs
                    if (authenticatorConfig != null) {
                        nameIdType = authenticatorConfig.getParameterMap().get(NAME_ID_TYPE);
                        if (StringUtils.isBlank(nameIdType)) {
                            // No NameID format set. Let's go with the default NameID format
                            nameIdType = NameIDType.UNSPECIFIED;
                        }
                    }
                }
                nameIdPolicy.setFormat(nameIdType);
                if (spEntityId != null && !spEntityId.isEmpty()) {
                    nameIdPolicy.setSPNameQualifier(spEntityId);
                }
                //nameIdPolicy.setSPNameQualifier(issuer);
                nameIdPolicy.setAllowCreate(true);
                authRequest.setNameIDPolicy(nameIdPolicy);
            }

            //Get the inbound SAMLRequest
            AuthnRequest inboundAuthnRequest = getAuthnRequest(context);

            RequestedAuthnContext requestedAuthnContext = buildRequestedAuthnContext(inboundAuthnRequest);
            if (requestedAuthnContext != null) {
                authRequest.setRequestedAuthnContext(requestedAuthnContext);
            }

            Extensions extensions = getSAMLExtensions(request);
            if (extensions != null) {
                authRequest.setExtensions(extensions);
            }

            return authRequest;
        } else {
            return super.buildAuthnRequest(request, isPassive, idpUrl, context);
        }

    }

    private RequestedAuthnContext buildRequestedAuthnContext(AuthnRequest inboundAuthnRequest) throws SAMLSSOException {

        /* AuthnContext */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = null;
        RequestedAuthnContext requestedAuthnContext = null;

        String includeAuthnContext = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                        .get(SSOConstants.AUTHENTICATOR_NAME);

        if (StringUtils.isNotEmpty(includeAuthnContext) && "yes".equalsIgnoreCase(includeAuthnContext)) {
            requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
            requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
            String authContextClassValues =
                    authenticatorConfig.getParameterMap().get(SAML_SSO_DEFAULT_AUTHN_CLASSES);

            String[] authContextClasses = authContextClassValues.split(",");

            if (authContextClasses != null && !ArrayUtils.isEmpty(authContextClasses)) {
                /* AuthnContextClass */
                for (String authContextClass : authContextClasses) {
                    AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
                    AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                            .buildObject(SAMLConstants.SAML20_NS,
                                    AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                    SAMLConstants.SAML20_PREFIX);
                    authnContextClassRef.setAuthnContextClassRef(authContextClass);
                    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
                }
            }

            /* Authentication Context Comparison Level */
            String authnContextComparison = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);
            if (StringUtils.isNotEmpty(authnContextComparison)) {
                if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
                }
            } else {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            }
        }

        return requestedAuthnContext;
    }

    private boolean isForceAuthenticate(AuthenticationContext context) {

        boolean forceAuthenticate = false;
        String forceAuthenticateProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
        if ("yes".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = true;
        } else if ("as_request".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = context.isForceAuthenticate();
        }
        return forceAuthenticate;
    }

}
