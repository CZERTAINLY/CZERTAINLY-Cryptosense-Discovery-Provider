package com.czertainly.cryptosense.certificate.discovery.api;

import com.czertainly.api.model.common.attribute.v2.content.ObjectAttributeContent;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import com.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import com.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import com.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/v1/discoveryProvider")
public class AnalyzerController {

    private AnalyzerService analyzerService;

    @Autowired
    public void setAnalyzerService(AnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    @RequestMapping(path = "/listAvailableProjects", method = RequestMethod.POST)
    List<ObjectAttributeContent> listAvailableProjects(@RequestBody AnalyzerRequestDto request) {
        List<AnalyzerProject> analyzerProjectList = analyzerService.getAvailableProjects(request);
        List<ObjectAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerProject analyzerProject : analyzerProjectList) {
            ObjectAttributeContent content = new ObjectAttributeContent(analyzerProject.getName(), analyzerProject);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }

    @RequestMapping(path = "/listAvailableReports/{projectId}", method = RequestMethod.POST)
    List<ObjectAttributeContent> listAvailableReports(@RequestBody AnalyzerRequestDto request, @PathVariable String projectId) {
        List<AnalyzerReport> analyzerReportList = analyzerService.getAvailableReports(request, projectId);
        List<ObjectAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerReport analyzerReport : analyzerReportList) {
            ObjectAttributeContent content = new ObjectAttributeContent(analyzerReport.getName(), analyzerReport);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }

    @RequestMapping(path = "/listCertificates/{reportId}", method = RequestMethod.POST)
    List<ObjectAttributeContent> listCertificates(@RequestBody AnalyzerRequestDto request, @PathVariable String reportId) {
        List<AnalyzerCertificate> analyzerCertificateList = analyzerService.listCertificates(request, reportId);
        List<ObjectAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerCertificate analyzerCertificate : analyzerCertificateList) {
            ObjectAttributeContent content = new ObjectAttributeContent(analyzerCertificate.getSubject(), analyzerCertificate);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }
}
