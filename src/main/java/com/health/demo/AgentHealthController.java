package com.health.demo;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/agents")
public class AgentHealthController {

    // agentId → last heartbeat
    private final ConcurrentMap<String, AgentHealthPayload> lastHealth = new ConcurrentHashMap<>();

    // Only updated when agent PUSHES data
    @PostMapping("/{agentId}/health")
    public ResponseEntity<?> updateHealth(
            @PathVariable String agentId,
            @RequestBody AgentHealthPayload payload) {

        payload.setAgentId(agentId);
        payload.setTimestamp(Instant.now());  // force server-side timestamp
        lastHealth.put(agentId, payload);     // UPDATE ONLY HERE

        return ResponseEntity.ok(Map.of(
                "status", "HEARTBEAT_RECEIVED",
                "agentId", agentId
        ));
    }

    // NO JSON UPDATE HERE — only health check
    @GetMapping("/{agentId}/health")
    public ResponseEntity<?> getHealth(@PathVariable String agentId) {

        AgentHealthPayload payload = lastHealth.get(agentId);

        if (payload == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                    "agentId", agentId,
                    "alive", false,
                    "reason", "No heartbeat ever received"
            ));
        }

        long seconds = Duration.between(
                payload.getTimestamp(),
                Instant.now()
        ).getSeconds();

        boolean alive = seconds <= 10;   //  DEAD AFTER 10 SECONDS

        return ResponseEntity.ok(Map.of(
                "agentId", agentId,
                "alive", alive,
                "lastSeenSecondsAgo", seconds,
                "lastHealth", payload   //  LAST DATA ONLY — NOT UPDATED
        ));
    }

    // View all agents
    @GetMapping("/health")
    public ResponseEntity<?> getAllAgents() {
        return ResponseEntity.ok(lastHealth);
    }

    @GetMapping("/{agentId}/download/{os}")
    public ResponseEntity<Resource> downloadScript(
            @PathVariable String agentId,
            @PathVariable String os) throws IOException {

        String fileName;

        if (os.equalsIgnoreCase("windows")) {
            fileName = "windows-hardening.ps1";
        } else if (os.equalsIgnoreCase("linux")) {
            fileName = "linux-hardening.sh";
        } else {
            return ResponseEntity.badRequest().build();
        }

        //  MUST use ClassPathResource for resources/static
        ClassPathResource resource =
                new ClassPathResource("static/scripts/" + fileName);

        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + fileName + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(resource.contentLength())
                .body(resource);
    }


    @GetMapping("/targets")
    public ResponseEntity<?> getTargetsForUI() {

        return ResponseEntity.ok(
                lastHealth.values().stream().map(payload -> {

                    long seconds = Duration.between(
                            payload.getTimestamp(),
                            Instant.now()
                    ).getSeconds();

                    boolean alive = seconds <= 10;

                    return Map.of(
                            "id", payload.getAgentId(),
                            "deviceName", payload.getHostname(),
                            "agentId", payload.getAgentId(),
                            "os", payload.getOs(),
                            "level", "Easy", // static for now
                            "lastSeen", seconds + " sec ago",
                            "status", alive ? "online" : "offline"
                    );

                }).toList()
        );
    }


}


