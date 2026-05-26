package com.devito.lifeengine.auth.service;

import com.devito.lifeengine.auth.events.UserRegisteredEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthTestService {

    private final ApplicationEventPublisher publisher;

    public AuthTestService(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void registerDummyUser(String email) {
        String userId = UUID.randomUUID().toString();
        publisher.publishEvent(new UserRegisteredEvent(userId, email, Instant.now()));
    }
}