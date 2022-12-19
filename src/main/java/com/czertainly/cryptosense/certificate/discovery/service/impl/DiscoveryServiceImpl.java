package com.czertainly.cryptosense.certificate.discovery.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.data.CredentialAttributeContentData;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.api.model.core.credential.CredentialDto;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import com.czertainly.cryptosense.certificate.discovery.dao.Certificate;
import com.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import com.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import com.czertainly.cryptosense.certificate.discovery.repository.CertificateRepository;
import com.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import com.czertainly.cryptosense.certificate.discovery.service.DiscoveryHistoryService;
import com.czertainly.cryptosense.certificate.discovery.service.DiscoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class DiscoveryServiceImpl implements DiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);

    private static final int PAGE_SIZE = 100;
    private AnalyzerService analyzerService;
    private CertificateRepository certificateRepository;
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    public void setAnalyzerService(AnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setDiscoveryHistoryService(DiscoveryHistoryService discoveryHistoryService) {
        this.discoveryHistoryService = discoveryHistoryService;
    }

    @Override
    public DiscoveryProviderDto getProviderDtoData(DiscoveryDataRequestDto request, DiscoveryHistory history) {
        DiscoveryProviderDto dto = new DiscoveryProviderDto();
        dto.setUuid(history.getUuid());
        dto.setName(history.getName());
        dto.setStatus(history.getStatus());
        dto.setMeta(AttributeDefinitionUtils.deserialize(history.getMeta(), MetadataAttribute.class));
        int totalCertificateSize = certificateRepository.findByDiscoveryId(history.getId()).size();
        dto.setTotalCertificatesDiscovered(totalCertificateSize);
        if (history.getStatus() == DiscoveryStatus.IN_PROGRESS) {
            dto.setCertificateData(new ArrayList<>());
            dto.setTotalCertificatesDiscovered(0);
        } else {
            Pageable page = PageRequest.of(request.getStartIndex(), request.getEndIndex());
            dto.setCertificateData(certificateRepository.findAllByDiscoveryId(history.getId(), page).stream().map(Certificate::mapToDto).collect(Collectors.toList()));
        }
        return dto;
    }

    @Override
    @Async
    public void discoverCertificate(DiscoveryRequestDto request, DiscoveryHistory history) {
        try {
            discoverCertificateInternal(request, history);
        } catch (Exception e) {
            history.setStatus(DiscoveryStatus.FAILED);
            throw e;
        }
    }

    @Override
    public void deleteDiscovery(String uuid) throws NotFoundException {
        DiscoveryHistory discoveryHistory = discoveryHistoryService.getHistoryByUuid(uuid);
        List<Certificate> certificates = certificateRepository.findByDiscoveryId(discoveryHistory.getId());
        certificateRepository.deleteAll(certificates);
        discoveryHistoryService.deleteHistory(discoveryHistory);
    }

    private void discoverCertificateInternal(DiscoveryRequestDto request, DiscoveryHistory history) throws NullPointerException {
        logger.info("Discovery initiated for the request with name {}", request.getName());
        String apiUrl = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeServiceImpl.ATTRIBUTE_API_URL, request.getAttributes(), StringAttributeContent.class).getData();
        CredentialAttributeContentData apiKeyCredential = AttributeDefinitionUtils.getCredentialContent("apiKey", request.getAttributes());
        final AnalyzerProject selectedProject = AttributeDefinitionUtils.getObjectAttributeContentData(AttributeServiceImpl.ATTRIBUTE_PROJECT, request.getAttributes(), AnalyzerProject.class).get(0);
        final AnalyzerReport selectedReport = AttributeDefinitionUtils.getObjectAttributeContentData(AttributeServiceImpl.ATTRIBUTE_REPORT, request.getAttributes(), AnalyzerReport.class).get(0);
        AnalyzerRequestDto analyzerRequestDto = new AnalyzerRequestDto();
        analyzerRequestDto.setApiUrl(apiUrl);
        analyzerRequestDto.setCredentialKind(apiKeyCredential);

        // get the certificates
        List<AnalyzerCertificate> listOfAllCertificates = new ArrayList<AnalyzerCertificate>();
        List<AnalyzerCertificate> listOfIncompleteCertificates = new ArrayList<AnalyzerCertificate>();
        if (selectedProject.getName().equals("ALL")) { // we need to search through all projects and reports
            logger.info("Searching for certificates in ALL projects and report");
            List<AnalyzerProject> listOfProjects = analyzerService.getAvailableProjects(analyzerRequestDto);
            for (AnalyzerProject analyzerProject : listOfProjects) {
                if (!analyzerProject.getName().equals("ALL")) {
                    List<AnalyzerReport> listOfReports = analyzerService.getAvailableReports(analyzerRequestDto, analyzerProject.getId());
                    for (AnalyzerReport analyzerReport : listOfReports) {
                        if (!analyzerReport.getName().equals("ALL")) {
                            logger.info("Going to search in project {} and report {}", analyzerProject.getId(), analyzerReport.getId());
                            List<AnalyzerCertificate> listOfCertificates;
                            try {
                                listOfCertificates = analyzerService.listCertificates(analyzerRequestDto, analyzerReport.getId());
                            } catch (Exception e) {
                                logger.error("Failed to discover Certificates: {}", e.getMessage());
                                history.setStatus(DiscoveryStatus.FAILED);
                                List<MetadataAttribute> meta = getReasonMeta(e.getMessage());
                                history.setMeta(AttributeDefinitionUtils.serialize(meta));
                                discoveryHistoryService.setHistory(history);
                                return;
                            }
                            listOfAllCertificates.addAll(listOfCertificates);
                            if (listOfCertificates != null && listOfCertificates.size() > 0) {
                                for (AnalyzerCertificate analyzerCertificate : listOfCertificates) {
                                    if (analyzerCertificate.getEncoded() != null) {
                                        parseAndCreateCertificateEntry(analyzerCertificate, history.getId(), analyzerProject, analyzerReport, apiUrl);
                                    } else {
                                        listOfIncompleteCertificates.add(analyzerCertificate);
                                    }
                                }
                            }
                        } else {
                            logger.info("Not going to search in ALL report");
                        }
                    }
                } else {
                    logger.info("Not going to search in ALL project");
                }
            }
        } else if (selectedReport.getName().equals("ALL")) { // we need to search through all reports in particular project
            logger.info("Searching for certificates in project {} and ALL reports", selectedProject.getId());
            List<AnalyzerReport> listOfReports = analyzerService.getAvailableReports(analyzerRequestDto, selectedProject.getId());
            for (AnalyzerReport analyzerReport : listOfReports) {
                if (!analyzerReport.getName().equals("ALL")) {
                    logger.info("Going to search in project {} and report {}", selectedProject.getId(), analyzerReport.getId());
                    List<AnalyzerCertificate> listOfCertificates;
                    try {
                        listOfCertificates = analyzerService.listCertificates(analyzerRequestDto, analyzerReport.getId());
                    } catch (Exception e) {
                        logger.error("Failed to discover Certificates: {}", e.getMessage());
                        history.setStatus(DiscoveryStatus.FAILED);
                        List<MetadataAttribute> meta = getReasonMeta(e.getMessage());
                        history.setMeta(AttributeDefinitionUtils.serialize(meta));
                        discoveryHistoryService.setHistory(history);
                        return;
                    }
                    listOfAllCertificates.addAll(listOfCertificates);
                    if (listOfCertificates != null && listOfCertificates.size() > 0) {
                        for (AnalyzerCertificate analyzerCertificate : listOfCertificates) {
                            if (analyzerCertificate.getEncoded() != null) {
                                parseAndCreateCertificateEntry(analyzerCertificate, history.getId(), selectedProject, analyzerReport, apiUrl);
                            } else {
                                listOfIncompleteCertificates.add(analyzerCertificate);
                            }
                        }
                    }
                } else {
                    logger.info("Not going to search in ALL report");
                }
            }
        } else { // there is a particular project and report to search for certificates
            logger.info("Going to search in project {} and report {}", selectedProject.getId(), selectedReport.getId());
            List<AnalyzerCertificate> listOfCertificates;
            try {
                listOfCertificates = analyzerService.listCertificates(analyzerRequestDto, selectedReport.getId());
            } catch (Exception e) {
                logger.error("Failed to discover Certificates: {}", e.getMessage());
                history.setStatus(DiscoveryStatus.FAILED);
                List<MetadataAttribute> meta = getReasonMeta(e.getMessage());
                history.setMeta(AttributeDefinitionUtils.serialize(meta));
                discoveryHistoryService.setHistory(history);
                return;
            }
            listOfAllCertificates.addAll(listOfCertificates);
            if (listOfCertificates != null && listOfCertificates.size() > 0) {
                for (AnalyzerCertificate analyzerCertificate : listOfCertificates) {
                    if (analyzerCertificate.getEncoded() != null) {
                        parseAndCreateCertificateEntry(analyzerCertificate, history.getId(), selectedProject, selectedReport, apiUrl);
                    } else {
                        listOfIncompleteCertificates.add(analyzerCertificate);
                    }
                }
            }
        }

        logger.info("Discovery {} has total of {} certificates", request.getName(), listOfAllCertificates == null ? 0 : listOfAllCertificates.size());
        history.setStatus(DiscoveryStatus.COMPLETED);

        history.setMeta(AttributeDefinitionUtils.serialize(getDiscoveryMeta(listOfAllCertificates == null ? 0 : listOfAllCertificates.size(), listOfIncompleteCertificates.size())));
        discoveryHistoryService.setHistory(history);
        logger.info("Discovery Completed. Name of the discovery is {}", request.getName());
    }

    private List<MetadataAttribute> getDiscoveryMeta(Integer totalCertificates, Integer incompleteCertificate) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Total Certificates
        MetadataAttribute attribute = new MetadataAttribute();
        attribute.setName("totalCertificates");
        attribute.setUuid("d3d8bdf8-60ed-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.INTEGER);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Total Number of Certificates Discovered");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Total Certificates Discovered");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new IntegerAttributeContent(totalCertificates.toString(), totalCertificates)));
        attributes.add(attribute);

        //Incomplete Certificates
        MetadataAttribute inCompleteAttribute = new MetadataAttribute();
        inCompleteAttribute.setName("incompleteCertificates");
        inCompleteAttribute.setUuid("d3d8c136-60ed-11ed-9b6a-0242ac120002");
        inCompleteAttribute.setContentType(AttributeContentType.INTEGER);
        inCompleteAttribute.setType(AttributeType.META);
        inCompleteAttribute.setDescription("Incomplete Certificates");

        MetadataAttributeProperties inCompleteAttributeProperties = new MetadataAttributeProperties();
        inCompleteAttributeProperties.setLabel("Incomplete Certificates");
        inCompleteAttributeProperties.setVisible(true);

        inCompleteAttribute.setProperties(inCompleteAttributeProperties);
        inCompleteAttribute.setContent(List.of(new IntegerAttributeContent(incompleteCertificate.toString(), incompleteCertificate)));
        attributes.add(inCompleteAttribute);

        return attributes;
    }

    private List<MetadataAttribute> getReasonMeta(String exception) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Exception Reason
        MetadataAttribute attribute = new MetadataAttribute();
        attribute.setName("reason");
        attribute.setUuid("4dcdd7fc-60ed-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Reason for failure");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Reason");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(exception)));
        attributes.add(attribute);

        return attributes;
    }

    private void parseAndCreateCertificateEntry(AnalyzerCertificate analyzerCertificate, Long discoveryId,
                                                AnalyzerProject analyzerProject, AnalyzerReport analyzerReport, String apiUrl) throws NullPointerException {
        logger.info("Parsing certificate {} from report {} and project {}", analyzerCertificate.getId(), analyzerReport.getId(), analyzerProject.getId());
        if (analyzerCertificate.getEncoded() != null) { // we want to include only certificates with full information
            URL url = null;
            try {
                url = new URL(apiUrl);
            } catch (MalformedURLException e) {
                logger.info("API URL is malformed: " + e.getMessage());
            }

            String certificateId = new String(Base64.getDecoder().decode(analyzerCertificate.getId())).split(":")[1];
            String projectId = new String(Base64.getDecoder().decode(analyzerProject.getId())).split(":")[1];
            String reportId = new String(Base64.getDecoder().decode(analyzerReport.getId())).split(":")[1];

            String analyzerUrl = "unrecognized";
            if (url != null) {
                analyzerUrl = url.getProtocol() + "://" + url.getHost() + "/report/" +
                        reportId + "/certificates/" + certificateId;
            }

            Certificate cert = new Certificate();

            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("analyzerUrl", analyzerUrl);
            meta.put("analyzerProjectName", analyzerProject.getName());
            meta.put("analyzerProjectId", projectId);
            meta.put("analyzerReportName", analyzerReport.getName());
            meta.put("analyzerReportId", reportId);
            meta.put("analyzerCertificateId", certificateId);
            meta.put("discoverySource", "Analyzer");
            cert.setUuid(UUID.randomUUID().toString());
            cert.setDiscoveryId(discoveryId);
            cert.setBase64Content(analyzerCertificate.getEncoded());
            cert.setMeta(AttributeDefinitionUtils.serialize(
                            getCertificateMeta(analyzerUrl,
                                    analyzerProject.getName(),
                                    projectId,
                                    analyzerReport.getName(),
                                    reportId,
                                    certificateId
                            )
                    )
            );

            certificateRepository.save(cert);
        }
    }

    private List<MetadataAttribute> getCertificateMeta(String url, String projectName, String projectId, String reportName, String reportId, String certId) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Analyzer URL
        MetadataAttribute attribute = new MetadataAttribute();
        attribute.setName("analyzerUrl");
        attribute.setUuid("88b104ec-60ee-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.INTEGER);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Analyzer URL from where the certificate is discovered");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Analyzer URL");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(url)));
        attributes.add(attribute);

        //Project Name
        MetadataAttribute projectNameAttribute = new MetadataAttribute();
        projectNameAttribute.setName("analyzerProjectName");
        projectNameAttribute.setUuid("88b107d0-60ee-11ed-9b6a-0242ac120002");
        projectNameAttribute.setContentType(AttributeContentType.INTEGER);
        projectNameAttribute.setType(AttributeType.META);
        projectNameAttribute.setDescription("Project Name from where the certificate is discovered");

        MetadataAttributeProperties projectNameProperties = new MetadataAttributeProperties();
        projectNameProperties.setLabel("Project Name");
        projectNameProperties.setVisible(true);

        projectNameAttribute.setProperties(projectNameProperties);
        projectNameAttribute.setContent(List.of(new StringAttributeContent(projectName)));
        attributes.add(projectNameAttribute);

        //Project ID
        MetadataAttribute projectIdAttribute = new MetadataAttribute();
        projectIdAttribute.setName("analyzerProjectId");
        projectIdAttribute.setUuid("88b109ce-60ee-11ed-9b6a-0242ac120002");
        projectIdAttribute.setContentType(AttributeContentType.STRING);
        projectIdAttribute.setType(AttributeType.META);
        projectIdAttribute.setDescription("Project ID from where the certificate is discovered");

        MetadataAttributeProperties projectIdAttributeProperties = new MetadataAttributeProperties();
        projectIdAttributeProperties.setLabel("Analyzer URL");
        projectIdAttributeProperties.setVisible(true);

        projectIdAttribute.setProperties(projectIdAttributeProperties);
        projectIdAttribute.setContent(List.of(new StringAttributeContent(projectId)));
        attributes.add(projectIdAttribute);

        //Report Name
        MetadataAttribute reportNameAttribute = new MetadataAttribute();
        reportNameAttribute.setName("analyzerReportName");
        reportNameAttribute.setUuid("88b10b2c-60ee-11ed-9b6a-0242ac120002");
        reportNameAttribute.setContentType(AttributeContentType.STRING);
        reportNameAttribute.setType(AttributeType.META);
        reportNameAttribute.setDescription("Report Name from where the certificate is discovered");

        MetadataAttributeProperties reportNameAttributeProperties = new MetadataAttributeProperties();
        reportNameAttributeProperties.setLabel("Report Name");
        reportNameAttributeProperties.setVisible(true);

        reportNameAttribute.setProperties(reportNameAttributeProperties);
        reportNameAttribute.setContent(List.of(new StringAttributeContent(reportName)));
        attributes.add(reportNameAttribute);

        //Report ID
        MetadataAttribute reportIdAttribute = new MetadataAttribute();
        reportIdAttribute.setName("analyzerReportId");
        reportIdAttribute.setUuid("88b1102c-60ee-11ed-9b6a-0242ac120002");
        reportIdAttribute.setContentType(AttributeContentType.STRING);
        reportIdAttribute.setType(AttributeType.META);
        reportIdAttribute.setDescription("Report ID from where the certificate is discovered");

        MetadataAttributeProperties reportIdAttributeProperties = new MetadataAttributeProperties();
        reportIdAttributeProperties.setLabel("Report ID");
        reportIdAttributeProperties.setVisible(true);

        reportIdAttribute.setProperties(reportIdAttributeProperties);
        reportIdAttribute.setContent(List.of(new StringAttributeContent(reportId)));
        attributes.add(reportIdAttribute);

        //Certificate ID
        MetadataAttribute certificateIdAttribute = new MetadataAttribute();
        certificateIdAttribute.setName("analyzerCertificateId");
        certificateIdAttribute.setUuid("88b1128e-60ee-11ed-9b6a-0242ac120002");
        certificateIdAttribute.setContentType(AttributeContentType.STRING);
        certificateIdAttribute.setType(AttributeType.META);
        certificateIdAttribute.setDescription("Certificate ID from where the certificate is discovered");

        MetadataAttributeProperties certificateIdAttributeProperties = new MetadataAttributeProperties();
        certificateIdAttributeProperties.setLabel("Certificate ID");
        certificateIdAttributeProperties.setVisible(true);

        certificateIdAttribute.setProperties(certificateIdAttributeProperties);
        certificateIdAttribute.setContent(List.of(new StringAttributeContent(url)));
        attributes.add(certificateIdAttribute);

        //Source
        MetadataAttribute sourceAttribute = new MetadataAttribute();
        sourceAttribute.setName("discoverySource");
        sourceAttribute.setUuid("0ee5fc56-60f0-11ed-9b6a-0242ac120002");
        sourceAttribute.setContentType(AttributeContentType.STRING);
        sourceAttribute.setType(AttributeType.META);
        sourceAttribute.setDescription("Discovery Source from where the certificate is discovered");

        MetadataAttributeProperties sourceAttributeProperties = new MetadataAttributeProperties();
        sourceAttributeProperties.setLabel("Discovery Source");
        sourceAttributeProperties.setVisible(true);

        sourceAttribute.setProperties(sourceAttributeProperties);
        sourceAttribute.setContent(List.of(new StringAttributeContent("Analyzer")));
        attributes.add(sourceAttribute);

        return attributes;
    }
}
