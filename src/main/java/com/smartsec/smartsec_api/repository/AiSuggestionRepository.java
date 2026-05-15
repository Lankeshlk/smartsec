package com.smartsec.smartsec_api.repository;

import com.smartsec.smartsec_api.model.AiSuggestion;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AiSuggestionRepository extends JpaRepository<AiSuggestion, Long> {
    Optional<AiSuggestion> findByVulnerabilityId(String vulnerabilityId);
}
