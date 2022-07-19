package org.czertainly.cryptosense.certificate.discovery.api;

import com.czertainly.api.model.common.attribute.content.JsonAttributeContent;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import org.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/v1/discoveryProvider")
public class AnalyzerController {

    @Autowired
    public void setAnalyzerService(AnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    private AnalyzerService analyzerService;

    @RequestMapping(path = "/listAvailableProjects", method = RequestMethod.POST)
    List<JsonAttributeContent> listAvailableProjects(@RequestBody AnalyzerRequestDto request) {
        List<AnalyzerProject> analyzerProjectList = analyzerService.getAvailableProjects(request);
        List<JsonAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerProject analyzerProject : analyzerProjectList) {
            JsonAttributeContent content = new JsonAttributeContent(analyzerProject.getName(), analyzerProject);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }

    @RequestMapping(path = "/listAvailableReports/{projectId}", method = RequestMethod.POST)
    List<JsonAttributeContent> listAvailableReports(@RequestBody AnalyzerRequestDto request, @PathVariable String projectId) {
        List<AnalyzerReport> analyzerReportList = analyzerService.getAvailableReports(request, projectId);
        List<JsonAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerReport analyzerReport : analyzerReportList) {
            JsonAttributeContent content = new JsonAttributeContent(analyzerReport.getName(), analyzerReport);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }

    @RequestMapping(path = "/listCertificates/{reportId}", method = RequestMethod.POST)
    List<JsonAttributeContent> listCertificates(@RequestBody AnalyzerRequestDto request, @PathVariable String reportId) {
        List<AnalyzerCertificate> analyzerCertificateList = analyzerService.listCertificates(request, reportId);
        List<JsonAttributeContent> jsonAttributeContentList = new ArrayList<>();
        for (AnalyzerCertificate analyzerCertificate : analyzerCertificateList) {
            JsonAttributeContent content = new JsonAttributeContent(analyzerCertificate.getSubject(), analyzerCertificate);
            jsonAttributeContentList.add(content);
        }
        return jsonAttributeContentList;
    }
}
