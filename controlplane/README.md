# Overview

This folder contains the control plane programs used by lemon and related analysis scripts.

├── lemon_controller   
│   └── controller.py                         --controller of Lemon   
├── per_flow_analysis   
│   ├── lemon_cpu_per_flow.py      --Python analysis tool of the Lemon sketch for                  │                                                                  evaluating performance and workload   
│   ├── jaqen_cpu_per_flow.py        --Python analysis tool of the Jaqen for    │                                                                  evaluating performance   
│   └──couper_cpu_per_flow.py      --Python analysis tool of the Couper for    │                                                                  evaluating performance   
├── pkt_send                                     --Send packets to mininet environment   
│   ├── pkg_sending.py   
│   └── routings.py   
├── traffic_generation                     --Generating attack traffic and Zipf FSD traffic   
│  ├── attack_gen.py   
│  ├── pkt_gen.py    
│  └── zpif_FSD.py   

└──README   
