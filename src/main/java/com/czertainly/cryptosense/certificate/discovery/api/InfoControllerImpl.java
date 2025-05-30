package com.czertainly.cryptosense.certificate.discovery.api;

import com.czertainly.api.interfaces.connector.InfoController;
import com.czertainly.api.model.client.connector.InfoResponse;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.cryptosense.certificate.discovery.EndpointsListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class InfoControllerImpl implements InfoController {
    private static final Logger logger = LoggerFactory.getLogger(InfoControllerImpl.class);

    @Autowired
    public void setEndpointsListener(EndpointsListener endpointsListener) {
        this.endpointsListener = endpointsListener;
    }

    private EndpointsListener endpointsListener;

    @Override
    public List<InfoResponse> listSupportedFunctions() {
    	logger.info("Listing the end points for Cryptosense Discovery Provider");
    	List<String> kind = List.of("Cryptosense");
    	List<InfoResponse> functions = new ArrayList<>(); 
        functions.add(new InfoResponse(kind, FunctionGroupCode.DISCOVERY_PROVIDER, endpointsListener.getEndpoints()));
        logger.debug("Functions of the connector is obtained. Value is {}", functions);
        return functions;
    }
}