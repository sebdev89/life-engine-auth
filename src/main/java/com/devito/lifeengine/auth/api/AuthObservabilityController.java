package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuthObservabilityAppService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Auth observability feeds — exposed only to admins via the core-app WebFlux security chain. */
@RestController
@RequestMapping("/api/auth")
public class AuthObservabilityController {

    private final AuthObservabilityAppService observability;

    public AuthObservabilityController(AuthObservabilityAppService observability) {
        this.observability = observability;
    }

    @GetMapping("/metrics/overview")
    public Mono<AuthDtos.AuthMetricsOverviewDto> metricsOverview() {
        return observability.overview();
    }

    @GetMapping("/timeline")
    public Flux<AuthDtos.AuthTimelineEntryDto> authTimeline(
            @RequestParam(name = "limit", defaultValue = "200") int limit) {
        return observability.timeline(limit);
    }
}
