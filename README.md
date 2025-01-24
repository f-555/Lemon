# Lemon: Network-wide DDoS Detection with Routing-Oblivious Per-flow Measurement

Network-wide DDoS (Distributed Denial-of-Service) detection enables early attack detection and mitigates victim losses. We propose Lemon, a routing-oblivious, resource-friendly, and scalable DDoS detection system that provides accurate detection of DDoS attacks without any assumption on the traffic routing.

## Source code overview

The folder structure is as follows:

artifact   
├── controlplane            --Contains Lemon controller, attack traffic generation script,    
│                                           packet sending and routing control script, and per-flow    
│                                           measurement result analysis script.   
├── lemon_bmv2           --Contains Lemon's P4 source code and related components    
│                                           required to run in Bmv2.   
├── lemon_hardware     --Contains Lemon's P4 source code in Tofino1.   
└── README

## Start with Lemon

Please install the corresponding dependencies and start lemon following the README in the corresponding folder of lemon_bmv2 and Lemon_hardware.

