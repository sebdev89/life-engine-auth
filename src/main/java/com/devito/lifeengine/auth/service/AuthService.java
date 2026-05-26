package com.devito.lifeengine.auth.service;

import com.devito.lifeengine.auth.api.AuthFacade;
import com.devito.lifeengine.shared.events.UserRegisteredEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Service
class AuthService implements AuthFacade {

    private final ApplicationEventPublisher publisher;

    AuthService(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void register(String userId, String email) {
        publisher.publishEvent(new UserRegisteredEvent(userId, email));
    }
}