package org.czertainly.cryptosense.certificate.discovery;

import com.czertainly.api.model.core.connector.EndpointDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.List;

@Component
public class EndpointsListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(EndpointsListener.class);

    public List<EndpointDto> endpoints = new ArrayList<>();

    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        ApplicationContext applicationContext = event.getApplicationContext();
        applicationContext.getBean(RequestMappingHandlerMapping.class)
                .getHandlerMethods()
                .entrySet().stream()
                .filter(e -> (e.getKey().getMethodsCondition().getMethods() != null && !e.getKey().getMethodsCondition().getMethods().isEmpty()))
                .forEach(e -> {
                    LOGGER.info("{} {} {}", e.getKey().getMethodsCondition().getMethods(),
                            e.getKey().getPatternValues(),
                            e.getValue().getMethod().getName());

                    EndpointDto endpoint = new EndpointDto();
                    endpoint.setMethod(e.getKey().getMethodsCondition().getMethods().iterator().next().name());
                    endpoint.setContext(e.getKey().getPatternValues().iterator().next());
                    endpoint.setName(e.getValue().getMethod().getName());
                    endpoints.add(endpoint);
                });
    }

    public List<EndpointDto> getEndpoints() {
        return this.endpoints;
    }
}
