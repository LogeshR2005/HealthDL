package com.backend.Backend.controller;


import com.backend.Backend.model.Job;
import com.backend.Backend.repo.JobRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin
public class AdminCommandController {

    @Autowired
    private JobRepo jobRepo;

    // Stores active commands per agent (IN-MEMORY)
    private final ConcurrentMap<String, String> agentCommands = new ConcurrentHashMap<>();

    // ====================================================
    // APPLY HARDENING COMMAND (FROM FRONTEND PLAY)
    // ====================================================
    @PostMapping("/hardening/{agentId}")
    public ResponseEntity<?> applyHardening(
            @PathVariable String agentId,
            @RequestBody Map<String, Object> payload
    ) {
        String os = payload.get("os").toString();

        agentCommands.put(agentId, "HARDENING");

        jobRepo.save(new Job(
                null,
                agentId,
                "Hardening triggered for " + os,
                "pending",
                Instant.now()
        ));

        return ResponseEntity.ok(Map.of(
                "status", "COMMAND_SENT",
                "agentId", agentId,
                "command", "HARDENING"
        ));
    }

    // ====================================================
    // ROLLBACK COMMAND (FROM FRONTEND RESTORE)
    // ====================================================
    @PostMapping("/rollback/{agentId}")
    public ResponseEntity<?> rollbackHardening(
            @PathVariable String agentId,
            @RequestBody Map<String, Object> payload
    ) {
        String os = payload.get("os").toString();

        agentCommands.put(agentId, "ROLLBACK");

        jobRepo.save(new Job(
                null,
                agentId,
                "Rollback triggered for " + os,
                "pending",
                Instant.now()
        ));

        return ResponseEntity.ok(Map.of(
                "status", "COMMAND_SENT",
                "agentId", agentId,
                "command", "ROLLBACK"
        ));
    }

    // ====================================================
    //  AGENT POLLS THIS ENDPOINT FOR COMMAND
    // ====================================================
    @GetMapping("/command/{agentId}")
    public ResponseEntity<?> getCommand(@PathVariable String agentId) {

        String command = agentCommands.getOrDefault(agentId, "NONE");

        //  After agent fetches it → delete auto
        if (!command.equals("NONE")) {
            agentCommands.remove(agentId);
        }

        return ResponseEntity.ok(Map.of(
                "agentId", agentId,
                "command", command
        ));
    }

    // ====================================================
    //  AGENT SENDS ACK AFTER EXECUTION
    // ====================================================
    @PostMapping("/{agentId}/ack")
    public ResponseEntity<?> receiveAck(
            @PathVariable String agentId,
            @RequestBody Map<String, Object> payload
    ) {
        String status = payload.get("status").toString();
        String message = payload.get("message").toString();

        jobRepo.save(
                new Job(null, agentId, message, status, Instant.now())
        );

        return ResponseEntity.ok(Map.of(
                "status", "ACK_RECEIVED",
                "agentId", agentId
        ));
    }
}

