package com.czertainly.cryptosense.certificate.discovery.api;

import com.czertainly.api.interfaces.connector.HealthController;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.HealthStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthControllerImpl implements HealthController {

    @Override
    public HealthDto checkHealth() {
        HealthDto health = new HealthDto();
        health.setStatus(HealthStatus.OK);
        health.setDescription("Connector is online and ready to serve request");
        return health;
    }
}
