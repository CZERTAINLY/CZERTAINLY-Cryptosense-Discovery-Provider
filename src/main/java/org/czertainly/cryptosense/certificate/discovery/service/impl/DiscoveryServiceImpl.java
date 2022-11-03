package org.czertainly.cryptosense.certificate.discovery.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.api.model.core.credential.CredentialDto;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import org.czertainly.cryptosense.certificate.discovery.dao.Certificate;
import org.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import org.czertainly.cryptosense.certificate.discovery.repository.CertificateRepository;
import org.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import org.czertainly.cryptosense.certificate.discovery.service.DiscoveryHistoryService;
import org.czertainly.cryptosense.certificate.discovery.service.DiscoveryService;
import org.czertainly.cryptosense.certificate.discovery.util.MetaDefinitions;
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
        dto.setMeta(MetaDefinitions.deserialize(history.getMeta()));
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
        Map<String, Object> meta = new LinkedHashMap<>();
        String apiUrl = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeServiceImpl.ATTRIBUTE_API_URL, request.getAttributes(), StringAttributeContent.class).getData();
        CredentialDto apiKeyCredential = AttributeDefinitionUtils.getCredentialContent("apiKey", request.getAttributes());
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
                                meta.put("reason", e.getMessage());
                                history.setMeta(MetaDefinitions.serialize(meta));
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
                        meta.put("reason", e.getMessage());
                        history.setMeta(MetaDefinitions.serialize(meta));
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
                meta.put("reason", e.getMessage());
                history.setMeta(MetaDefinitions.serialize(meta));
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

        meta.put("totalCertificates", listOfAllCertificates == null ? 0 : listOfAllCertificates.size());
        meta.put("incompleteCertificates", listOfIncompleteCertificates.size());

        history.setMeta(MetaDefinitions.serialize(meta));
        discoveryHistoryService.setHistory(history);
        logger.info("Discovery Completed. Name of the discovery is {}", request.getName());
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
            cert.setMeta(MetaDefinitions.serialize(meta));

            certificateRepository.save(cert);
        }
    }
}
