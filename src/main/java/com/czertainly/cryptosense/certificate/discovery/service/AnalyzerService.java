package com.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import com.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;

import java.util.List;

public interface AnalyzerService {

    List<AnalyzerProject> getAvailableProjects(AnalyzerRequestDto request);

    List<AnalyzerReport> getAvailableReports(AnalyzerRequestDto request, String projectId);

    List<AnalyzerCertificate> listCertificates(AnalyzerRequestDto request, String reportId);
}
