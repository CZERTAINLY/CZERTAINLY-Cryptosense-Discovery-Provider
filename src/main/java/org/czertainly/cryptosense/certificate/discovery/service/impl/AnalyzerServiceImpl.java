package org.czertainly.cryptosense.certificate.discovery.service.impl;

import com.czertainly.api.model.common.attribute.content.BaseAttributeContent;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.GraphqlRequestBody;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerDto;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerEdgesDto;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import org.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import org.czertainly.cryptosense.certificate.discovery.util.GraphqlSchemaReaderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class AnalyzerServiceImpl implements AnalyzerService {

    private static final Logger logger = LoggerFactory.getLogger(AnalyzerServiceImpl.class);

    //Value for maximum response byte size for webclient. The value is set to 100 MB to handle the response even if Cryptosense sends a larger volume than expected
    private static final Integer MAX_BYTE_COUNT = 100 * 1024 * 1024;

    @Override
    public List<AnalyzerProject> getAvailableProjects(AnalyzerRequestDto request) {

        WebClient webClient = WebClient.builder().build();
        GraphqlRequestBody graphQLRequestBody = new GraphqlRequestBody();

        String query = null;
        try {
            query = GraphqlSchemaReaderUtil.getSchemaFromFileName("listProjects");
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        //final String variables = GraphqlSchemaReaderUtil.getSchemaFromFileName("variables");

        graphQLRequestBody.setQuery(query);
        //graphQLRequestBody.setVariables(variables.replace("countryCode", countryCode));
        //CredentialDto apiKey = AttributeDefinitionUtils.getCredentialValue("apiKey", request.getApiKey().getAttributes());
        String apiKey = AttributeDefinitionUtils.getAttributeContentValue("apiKey", request.getCredentialKind().getAttributes(), BaseAttributeContent.class);
        AnalyzerDto response = webClient.post()
                .uri(request.getApiUrl())
                .header("API-KEY", apiKey)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(graphQLRequestBody)
                .retrieve()
                .bodyToMono(AnalyzerDto.class)
                .block();

        List<AnalyzerProject> listOfProjects = new ArrayList<>();
        if(response == null || response.getData() == null){
            return listOfProjects;
        }
        List<AnalyzerEdgesDto> edges = response.getData().getViewer().getOrganization().getProjects().getEdges();
        for (AnalyzerEdgesDto edge : edges) {
            AnalyzerProject project = new AnalyzerProject(
                    edge.getNode().getId(),
                    edge.getNode().getName(),
                    edge.getNode().getApi()
            );
            listOfProjects.add(project);
        }

        if (!listOfProjects.isEmpty() && listOfProjects.size() > 1) {
            // include ALL project identified in the list
            AnalyzerProject project = new AnalyzerProject(
                    "ALL",
                    "ALL",
                    "ALL"
            );
            listOfProjects.add(project);
        }

        return listOfProjects;
    }

    @Override
    public List<AnalyzerReport> getAvailableReports(AnalyzerRequestDto request, String projectId) {
        List<AnalyzerReport> listOfReports = new ArrayList<>();

        if (projectId.equals("ALL")) { // search through all available reports
            AnalyzerReport project = new AnalyzerReport(
                    "ALL",
                    "ALL",
                    "ALL"
            );
            listOfReports.add(project);
        } else { // get available report for the project

            WebClient webClient = WebClient.builder().build();
            GraphqlRequestBody graphQLRequestBody = new GraphqlRequestBody();

            String query = null;
            String variables = null;
            try {
                query = GraphqlSchemaReaderUtil.getSchemaFromFileName("listReportsInProject");
                variables = GraphqlSchemaReaderUtil.getSchemaFromFileName("variables");
            } catch (IOException e) {
                logger.error(e.getMessage());
            }

            graphQLRequestBody.setQuery(query);
            if(variables != null) {
                graphQLRequestBody.setVariables(variables.replace("projectId", projectId));
            }

            String apiKey = AttributeDefinitionUtils.getAttributeContentValue("apiKey", request.getCredentialKind().getAttributes(), BaseAttributeContent.class);

            AnalyzerDto response = webClient.post()
                    .uri(request.getApiUrl())
                    .header("API-KEY", apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(graphQLRequestBody)
                    .retrieve()
                    .bodyToMono(AnalyzerDto.class)
                    .block();

            if(response == null || response.getData() == null){
                return listOfReports;
            }
            List<AnalyzerEdgesDto> edges = response.getData().getNode().getReports().getEdges();
            for (AnalyzerEdgesDto edge : edges) {
                AnalyzerReport project = new AnalyzerReport(
                        edge.getNode().getId(),
                        edge.getNode().getName(),
                        edge.getNode().get__typename()
                );
                listOfReports.add(project);
            }

            if (!listOfReports.isEmpty() && listOfReports.size() > 1) {
                // include ALL project identified in the list
                AnalyzerReport project = new AnalyzerReport(
                        "ALL",
                        "ALL",
                        "ALL"
                );
                listOfReports.add(project);
            }
        }

        return listOfReports;
    }

    @Override
    public List<AnalyzerCertificate> listCertificates(AnalyzerRequestDto request, String reportId) {
        WebClient webClient = WebClient.builder().codecs(configurer -> configurer
                        .defaultCodecs()
                        .maxInMemorySize(MAX_BYTE_COUNT)).build();
        GraphqlRequestBody graphQLRequestBody = new GraphqlRequestBody();

        String query = null;
        String variables = null;
        try {
            query = GraphqlSchemaReaderUtil.getSchemaFromFileName("listCertificatesInReport");
            variables = GraphqlSchemaReaderUtil.getSchemaFromFileName("variables");
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

        graphQLRequestBody.setQuery(query);
        if(variables != null) {
            graphQLRequestBody.setVariables(variables.replace("reportId", reportId));
        }

        String apiKey = AttributeDefinitionUtils.getAttributeContentValue("apiKey", request.getCredentialKind().getAttributes(), BaseAttributeContent.class);

        AnalyzerDto response = webClient.post()
                .uri(request.getApiUrl())
                .header("API-KEY", apiKey)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(graphQLRequestBody)
                .retrieve()
                .bodyToMono(AnalyzerDto.class)
                .block();
        List<AnalyzerCertificate> listOfCertificates = new ArrayList<>();
        if(response == null || response.getData() == null){
            return listOfCertificates;
        }

        List<AnalyzerEdgesDto> edges = response.getData().getNode().getCertificates().getEdges();
        for (AnalyzerEdgesDto edge : edges) {
            AnalyzerCertificate project = new AnalyzerCertificate(
                    edge.getNode().getId(),
                    edge.getNode().getSerialNumber(),
                    edge.getNode().getSubject(),
                    edge.getNode().getIssuer(),
                    edge.getNode().getFingerprint(),
                    edge.getNode().getEncoded()
            );
            listOfCertificates.add(project);
        }

        return listOfCertificates;
    }
}
