package com.smartsec.smartsec_api.repository;

import com.smartsec.smartsec_api.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    @Query("SELECT s FROM Scan s LEFT JOIN FETCH s.vulnerabilities WHERE s.user.id = :userId ORDER BY s.scannedAt DESC")
    List<Scan> findByUserIdOrderByScannedAtDesc(@Param("userId") Long userId);
}
