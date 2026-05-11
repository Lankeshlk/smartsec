package com.smartsec.smartsec_api.repository;

import com.smartsec.smartsec_api.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByUserIdOrderByScannedAtDesc(Long userId);
}
