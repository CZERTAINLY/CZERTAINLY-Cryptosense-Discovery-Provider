package com.czertainly.cryptosense.certificate.discovery.service.impl;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.v2.constraint.RegexpAttributeConstraint;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cryptosense.certificate.discovery.service.AttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class AttributeServiceImpl implements AttributeService {
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
    private static final Logger logger = LoggerFactory.getLogger(AttributeServiceImpl.class);

    @Override
    public List<BaseAttribute> getAttributes(String kind) {

        List<BaseAttribute> attributes = new ArrayList<>();

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

        logger.debug("Attributes constructed. {}", attributes);
        return attributes;
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);
        return true;
    }

    private DataAttribute getAnalyzerApiUrlAttribute() {
        DataAttribute apiUrl = new DataAttribute();
        apiUrl.setUuid("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setName(ATTRIBUTE_API_URL);
        apiUrl.setType(AttributeType.DATA);
        apiUrl.setContentType(AttributeContentType.STRING);
        DataAttributeProperties apiUrlProperties = new DataAttributeProperties();
        apiUrlProperties.setLabel(ATTRIBUTE_API_URL_LABEL);
        apiUrlProperties.setRequired(true);
        apiUrlProperties.setReadOnly(false);
        apiUrlProperties.setVisible(true);
        apiUrlProperties.setList(false);
        apiUrlProperties.setMultiSelect(false);
        apiUrl.setProperties(apiUrlProperties);
        apiUrl.setContent(List.of(new StringAttributeContent("https://analyzer.cryptosense.com/api/v2")));
        apiUrl.setDescription("Cryptosense Analyzer URL to access the API");
        apiUrl.setConstraints(List.of(new RegexpAttributeConstraint(
                "Cryptosense Analyzer URL",
                "Enter the valid URL",
                "^(http:\\/\\/www\\.|https:\\/\\/www\\.|http:\\/\\/|https:\\/\\/)?[a-z0-9]+([\\-\\.]{1}[a-z0-9]+)*\\.[a-z]{2,5}(:[0-9]{1,5})?(\\/.*)?$")));
        return apiUrl;
    }

    private DataAttribute getAnalyzerApiKeyAttribute() {
        DataAttribute credentialKind = new DataAttribute();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2e2d16c99c56");
        credentialKind.setName(ATTRIBUTE_CREDENTIAL_KIND);
        credentialKind.setDescription("API Key to authorize communication with the Analyzer");
        credentialKind.setType(AttributeType.DATA);
        credentialKind.setContentType(AttributeContentType.STRING);
        DataAttributeProperties credentialKindProperties = new DataAttributeProperties();
        credentialKindProperties.setLabel(ATTRIBUTE_CREDENTIAL_KIND_LABEL);
        credentialKindProperties.setRequired(false);
        credentialKindProperties.setReadOnly(false);
        credentialKindProperties.setVisible(false);
        credentialKindProperties.setList(false);
        credentialKindProperties.setMultiSelect(false);
        credentialKind.setProperties(credentialKindProperties);
        credentialKind.setContent(List.of(new StringAttributeContent("ApiKey")));
        return credentialKind;
    }

    private DataAttribute getAnalyzerApiKeyCredentialAttribute() {
        DataAttribute credentialKind = new DataAttribute();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2a2d16c99c57");
        credentialKind.setName(ATTRIBUTE_CREDENTIAL);
        credentialKind.setDescription("Credential for the communication");
        credentialKind.setType(AttributeType.DATA);
        credentialKind.setContentType(AttributeContentType.CREDENTIAL);
        DataAttributeProperties credentialKindProperties = new DataAttributeProperties();
        credentialKindProperties.setLabel(ATTRIBUTE_CREDENTIAL_LABEL);
        credentialKindProperties.setRequired(true);
        credentialKindProperties.setReadOnly(false);
        credentialKindProperties.setVisible(true);
        credentialKindProperties.setList(true);
        credentialKindProperties.setMultiSelect(false);
        credentialKind.setProperties(credentialKindProperties);

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

    private DataAttribute getProjectsAttribute() {
        DataAttribute projectsList = new DataAttribute();
        projectsList.setUuid("131f64b8-52e4-4cb8-b7de-63ca61c35209");
        projectsList.setName(ATTRIBUTE_PROJECT);
        projectsList.setDescription("List of available projects");
        projectsList.setType(AttributeType.DATA);
        projectsList.setContentType(AttributeContentType.OBJECT);
        DataAttributeProperties projectsListProperties = new DataAttributeProperties();
        projectsListProperties.setLabel(ATTRIBUTE_PROJECT_LABEL);
        projectsListProperties.setRequired(true);
        projectsListProperties.setReadOnly(false);
        projectsListProperties.setVisible(true);
        projectsListProperties.setList(true);
        projectsListProperties.setMultiSelect(false);
        projectsList.setProperties(projectsListProperties);
        projectsList.setContent(List.of());

        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(
                "apiUrl",
                "apiUrl",
                AttributeValueTarget.BODY));
        mappings.add(new AttributeCallbackMapping(
                ATTRIBUTE_CREDENTIAL,
                AttributeType.DATA,
                AttributeContentType.CREDENTIAL,
                "credentialKind",
                Collections.singleton(AttributeValueTarget.BODY)));

        AttributeCallback listProjectsCallback = new AttributeCallback();
        listProjectsCallback.setCallbackContext("/v1/discoveryProvider/listAvailableProjects");
        listProjectsCallback.setCallbackMethod("POST");
        listProjectsCallback.setMappings(mappings);
        projectsList.setAttributeCallback(listProjectsCallback);

        return projectsList;
    }

    private DataAttribute getReportsAttribute() {
        DataAttribute reportsList = new DataAttribute();
        reportsList.setUuid("131f64b8-52e4-4db8-b7de-63ca61c35209");
        reportsList.setName(ATTRIBUTE_REPORT);
        reportsList.setDescription("List of available reports");
        reportsList.setType(AttributeType.DATA);
        reportsList.setContentType(AttributeContentType.OBJECT);
        DataAttributeProperties reportsListProperties = new DataAttributeProperties();
        reportsListProperties.setLabel(ATTRIBUTE_REPORT_LABEL);
        reportsListProperties.setRequired(true);
        reportsListProperties.setReadOnly(false);
        reportsListProperties.setVisible(true);
        reportsListProperties.setList(true);
        reportsListProperties.setMultiSelect(false);
        reportsList.setProperties(reportsListProperties);
        reportsList.setContent(List.of());

        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(
                "apiUrl",
                "apiUrl",
                AttributeValueTarget.BODY));
        mappings.add(new AttributeCallbackMapping(
                ATTRIBUTE_CREDENTIAL,
                AttributeType.DATA,
                AttributeContentType.CREDENTIAL,
                "credentialKind",
                Collections.singleton(AttributeValueTarget.BODY)));
        mappings.add(new AttributeCallbackMapping(
                "project.data.id",
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
