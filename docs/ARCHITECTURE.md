# Nexus-Sec Architecture Diagram

This file contains the architecture diagram in Mermaid format for GitHub rendering.

## System Architecture

```mermaid
graph TB
    subgraph "External Sources"
        TI1[AbuseIPDB]
        TI2[AlienVault OTX]
        TI3[VirusTotal]
        SIEM1[Splunk]
        SIEM2[Elasticsearch]
        SIEM3[Syslog Server]
    end

    subgraph "Nexus-Sec Platform"
        subgraph "Detection Layer"
            DA[Detection Agents<br/>Claude AI-Powered]
            TH[Threat Hunting Engine<br/>IOC & Behavioral]
        end

        subgraph "Intelligence Layer"
            TIM[Threat Intelligence Manager<br/>IOC Enrichment & Scoring]
            CORR[Correlation Engine<br/>Event Analysis]
        end

        subgraph "Response Layer"
            PE[Playbook Engine<br/>Automated Response]
            RA1[Isolate Host]
            RA2[Block IP]
            RA3[Collect Evidence]
            RA4[Quarantine File]
            RA5[Send Alert]
            RA6[Create Ticket]
        end

        subgraph "Integration Layer"
            SIEMMGR[SIEM Manager<br/>Event Forwarding]
        end
    end

    subgraph "Target Environment"
        EDR[EDR/Endpoint]
        FW[Firewall]
        LOGS[Log Sources]
        NET[Network Devices]
    end

    %% Data Flow
    TI1 --> TIM
    TI2 --> TIM
    TI3 --> TIM
    
    LOGS --> DA
    LOGS --> TH
    
    DA --> CORR
    TH --> CORR
    TIM --> CORR
    
    CORR --> PE
    
    PE --> RA1
    PE --> RA2
    PE --> RA3
    PE --> RA4
    PE --> RA5
    PE --> RA6
    
    RA1 --> EDR
    RA2 --> FW
    RA3 --> EDR
    RA4 --> EDR
    RA5 --> LOGS
    RA6 --> LOGS
    
    DA --> SIEMMGR
    TH --> SIEMMGR
    PE --> SIEMMGR
    
    SIEMMGR --> SIEM1
    SIEMMGR --> SIEM2
    SIEMMGR --> SIEM3

    %% Styling
    classDef detection fill:#4CAF50,stroke:#2E7D32,stroke-width:2px,color:#fff
    classDef intelligence fill:#2196F3,stroke:#1565C0,stroke-width:2px,color:#fff
    classDef response fill:#FF9800,stroke:#E65100,stroke-width:2px,color:#fff
    classDef integration fill:#9C27B0,stroke:#6A1B9A,stroke-width:2px,color:#fff
    classDef external fill:#607D8B,stroke:#37474F,stroke-width:2px,color:#fff
    
    class DA,TH detection
    class TIM,CORR intelligence
    class PE,RA1,RA2,RA3,RA4,RA5,RA6 response
    class SIEMMGR integration
    class TI1,TI2,TI3,SIEM1,SIEM2,SIEM3,EDR,FW,LOGS,NET external
```

## Component Descriptions

### Detection Layer
- **Detection Agents**: AI-powered autonomous agents using Claude for threat analysis
- **Threat Hunting Engine**: Proactive IOC hunting and behavioral analytics

### Intelligence Layer
- **Threat Intelligence Manager**: Enriches IOCs with reputation data from multiple feeds
- **Correlation Engine**: Combines data from multiple sources to identify complex threats

### Response Layer
- **Playbook Engine**: Orchestrates automated incident response workflows
- **Response Actions**: 6 built-in actions for comprehensive incident handling

### Integration Layer
- **SIEM Manager**: Forwards all security events to enterprise SIEM platforms
