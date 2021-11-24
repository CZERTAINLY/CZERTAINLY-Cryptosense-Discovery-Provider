package org.czertainly.cryptosense.certificate.discovery.api;

import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerCertificate;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerProject;
import org.czertainly.cryptosense.certificate.discovery.cryptosense.AnalyzerReport;
import org.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import org.czertainly.cryptosense.certificate.discovery.service.AnalyzerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/discoveryProvider")
public class AnalyzerController {

    @Autowired
    private AnalyzerService analyzerService;

    @RequestMapping(path = "/listAvailableProjects", method = RequestMethod.POST)
    List<AnalyzerProject> listAvailableProjects(@RequestBody AnalyzerRequestDto request) {
        return analyzerService.getAvailableProjects(request);
    }

    @RequestMapping(path = "/listAvailableReports/{projectId}", method = RequestMethod.POST)
    List<AnalyzerReport> listAvailableReports(@RequestBody AnalyzerRequestDto request, @PathVariable String projectId) {
        return analyzerService.getAvailableReports(request, projectId);
    }

    @RequestMapping(path = "/listCertificates/{reportId}", method = RequestMethod.POST)
    List<AnalyzerCertificate> listCertificates(@RequestBody AnalyzerRequestDto request, @PathVariable String reportId) {
        return analyzerService.listCertificates(request, reportId);
    }
}
