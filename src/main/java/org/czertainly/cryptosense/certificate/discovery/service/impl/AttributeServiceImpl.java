package org.czertainly.cryptosense.certificate.discovery.service.impl;

import com.czertainly.api.model.common.*;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.czertainly.cryptosense.certificate.discovery.service.AttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class AttributeServiceImpl implements AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeServiceImpl.class);

    public static final String ATTRIBUTE_API_URL = "apiUrl";
    public static final String ATTRIBUTE_CREDENTIAL_KIND = "credentialKind";
    public static final String ATTRIBUTE_CREDENTIAL = "apiKey";
    public static final String ATTRIBUTE_PROJECT = "project";
    public static final String ATTRIBUTE_REPORT = "report";

    public static final String ATTRIBUTE_API_URL_LABEL = "Analyzer API URL";
    public static final String ATTRIBUTE_CREDENTIAL_KIND_LABEL = "Credential Kind";
    public static final String ATTRIBUTE_CREDENTIAL_LABEL = "API Key";
    public static final String ATTRIBUTE_PROJECT_LABEL = "Project";
    public static final String ATTRIBUTE_REPORT_LABEL = "Report";


    @Override
    public List<AttributeDefinition> getAttributes(String kind) {

        List<AttributeDefinition> attributes = new ArrayList<>();

        /**
         * ANALYZER API URL
         */
        attributes.add(getAnalyzerApiUrlAttribute());
        /**
         * CREDENTIAL KIND
         */
        attributes.add(getAnalyzerApiKeyAttribute());
        /**
         * CREDENTIAL KIND API KEY
         */
        attributes.add(getAnalyzerApiKeyCredentialAttribute());
        /**
         * LIST OF PROJECTS
         */
        attributes.add(getProjectsAttribute());
        /**
         * LIST OF REPORTS
         */
        attributes.add(getReportsAttribute());

        logger.debug("Attributes constructed. {}", attributes.toString());
        return attributes;
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);
        return true;
    }

    private AttributeDefinition getAnalyzerApiUrlAttribute() {
        AttributeDefinition apiUrl = new AttributeDefinition();
        apiUrl.setUuid("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setName(ATTRIBUTE_API_URL);
        apiUrl.setLabel(ATTRIBUTE_API_URL_LABEL);
        apiUrl.setType(BaseAttributeDefinitionTypes.STRING);
        apiUrl.setRequired(true);
        apiUrl.setReadOnly(false);
        apiUrl.setVisible(true);
        apiUrl.setValue("https://analyzer.cryptosense.com/api/v2");
        apiUrl.setDescription("Cryptosense Analyzer URL to access the API");
        apiUrl.setValidationRegex("^(http:\\/\\/www\\.|https:\\/\\/www\\.|http:\\/\\/|https:\\/\\/)?[a-z0-9]+([\\-\\.]{1}[a-z0-9]+)*\\.[a-z]{2,5}(:[0-9]{1,5})?(\\/.*)?$");
        return apiUrl;
    }

    private AttributeDefinition getAnalyzerApiKeyAttribute() {
        AttributeDefinition credentialKind = new AttributeDefinition();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2e2d16c99c56");
        credentialKind.setName(ATTRIBUTE_CREDENTIAL_KIND);
        credentialKind.setLabel(ATTRIBUTE_CREDENTIAL_KIND_LABEL);
        credentialKind.setDescription("API Key to authorize communication with the Analyzer");
        credentialKind.setType(BaseAttributeDefinitionTypes.STRING);
        credentialKind.setRequired(false);
        credentialKind.setReadOnly(true);
        credentialKind.setVisible(false);
        credentialKind.setValue("ApiKey");
        return credentialKind;
    }

    private AttributeDefinition getAnalyzerApiKeyCredentialAttribute() {
        AttributeDefinition credentialKind = new AttributeDefinition();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2a2d16c99c57");
        credentialKind.setName(ATTRIBUTE_CREDENTIAL);
        credentialKind.setLabel(ATTRIBUTE_CREDENTIAL_LABEL);
        credentialKind.setDescription("Credential for the communication");
        credentialKind.setType(BaseAttributeDefinitionTypes.CREDENTIAL);
        credentialKind.setRequired(true);
        credentialKind.setReadOnly(false);
        credentialKind.setVisible(true);

        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(
                "credentialKind",
                AttributeValueTarget.PATH_VARIABLE,
                "ApiKey"));

        AttributeCallback listCredentialCallback = new AttributeCallback();
        listCredentialCallback.setCallbackContext("core/getCredentials");
        listCredentialCallback.setCallbackMethod("GET");
        listCredentialCallback.setMappings(mappings);
        credentialKind.setAttributeCallback(listCredentialCallback);

        return credentialKind;
    }

    private AttributeDefinition getProjectsAttribute() {
        AttributeDefinition projectsList = new AttributeDefinition();
        projectsList.setUuid("131f64b8-52e4-4cb8-b7de-63ca61c35209");
        projectsList.setName(ATTRIBUTE_PROJECT);
        projectsList.setLabel(ATTRIBUTE_PROJECT_LABEL);
        projectsList.setDescription("List of available projects");
        projectsList.setType(BaseAttributeDefinitionTypes.LIST);
        projectsList.setRequired(true);
        projectsList.setReadOnly(false);
        projectsList.setValue(true);

        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(
                "apiUrl",
                "apiUrl",
                AttributeValueTarget.BODY));
        mappings.add(new AttributeCallbackMapping(
                ATTRIBUTE_CREDENTIAL,
                BaseAttributeDefinitionTypes.CREDENTIAL,
                "credentialKind",
                AttributeValueTarget.BODY));

        AttributeCallback listProjectsCallback = new AttributeCallback();
        listProjectsCallback.setCallbackContext("/v1/discoveryProvider/listAvailableProjects");
        listProjectsCallback.setCallbackMethod("POST");
        listProjectsCallback.setMappings(mappings);
        projectsList.setAttributeCallback(listProjectsCallback);

        return projectsList;
    }

    private AttributeDefinition getReportsAttribute() {
        AttributeDefinition reportsList = new AttributeDefinition();
        reportsList.setUuid("131f64b8-52e4-4db8-b7de-63ca61c35209");
        reportsList.setName(ATTRIBUTE_REPORT);
        reportsList.setLabel(ATTRIBUTE_REPORT_LABEL);
        reportsList.setDescription("List of available reports");
        reportsList.setType(BaseAttributeDefinitionTypes.LIST);
        reportsList.setRequired(true);
        reportsList.setReadOnly(false);
        reportsList.setValue(true);

        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(
                "apiUrl",
                "apiUrl",
                AttributeValueTarget.BODY));
        mappings.add(new AttributeCallbackMapping(
                ATTRIBUTE_CREDENTIAL,
                BaseAttributeDefinitionTypes.CREDENTIAL,
                "credentialKind",
                AttributeValueTarget.BODY));
        mappings.add(new AttributeCallbackMapping(
                "project",
                "projectId",
                AttributeValueTarget.PATH_VARIABLE));

        AttributeCallback listReportsCallback = new AttributeCallback();
        listReportsCallback.setCallbackContext("/v1/discoveryProvider/listAvailableReports/{projectId}");
        listReportsCallback.setCallbackMethod("POST");
        listReportsCallback.setMappings(mappings);
        reportsList.setAttributeCallback(listReportsCallback);

        return reportsList;
    }
}
