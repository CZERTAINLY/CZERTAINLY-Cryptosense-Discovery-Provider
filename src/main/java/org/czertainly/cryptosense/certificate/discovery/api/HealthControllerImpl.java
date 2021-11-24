package org.czertainly.cryptosense.certificate.discovery.api;

import com.czertainly.api.interfaces.HealthController;
import com.czertainly.api.model.HealthDto;
import com.czertainly.api.model.HealthStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthControllerImpl implements HealthController {

    @Override
    public HealthDto checkHealth() {
        HealthDto health = new HealthDto();
        health.setStatus(HealthStatus.OK);
        health.setDescription("Everything seems to be working...");
        return health;
    }
}
