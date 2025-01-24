# Overview

This file is Bmv2 implementation of Lemon. The folder structure is as follows:   

├── baselines                     -- P4 sources of baselines   
├── divider.p4                    -- simple switch for packet sending   
├── p4app.json                  -- configuration file of network   
├── topologies                   -- topologies, each contain a p4app.json   
├── s1-commands.txt       -- configure hash function in Lemon   
├── measurement.p4       -- P4 source of Lemon    
└── README   

# Building and Running

## 1. System requirement

Lemon depends on the following programs in the given order:   

+ [protobuf](https://github.com/protocolbuffers/protobuf) v3.18.1

+ [grpc](https://github.com/grpc/grpc) v1.43.2

+ [PI](https://github.com/p4lang/PI) v0.1.0

+ [p4c](https://github.com/p4lang/p4c) v1.2.2.1

+ [bmv2](https://github.com/p4lang/behavioral-model) v1.15.0

+ [mininet](https://github.com/mininet/mininet) latest

+ [p4-utils](https://github.com/nsg-ethz/p4-utils) latest

## 2. Start with Lemon

You can run `sudo p4run` to directly start Lemon.

```
sudo p4run
```

If lemon starts successfully, you will enter the mininet terminal.

```
*** Starting CLI:
mininet>
```

## 3. Packet sending

We provide two ways to send packets in Lemon:

(1) Send packets in mininet with /devider.p4

> Please include `divider.p4` in `p4app.json` and connect it to all measurement points to send packets directly to the switch corresponding to `devider.p4`.

(2) Send packets in mininet with /controlplane/pkt_send/pkg_sending.py (recommend)

> Run `pkg_sending.py` directly.
> 
> ```
> sudu python3 /controlplane/pkt_send/pkg_sending.py
> ```

## 4. Start controller for data collecting

Run python control plane with  /controlplane/lemon_controller/controller.py.

```
sudu python3 /controlplane/lemon_controller/controller.py
```

If Lemon controller starts successfully, you will see the following information.

```
p4switch: s01 thrift_port: 9090
p4switch: s02 thrift_port: 9091
...
```

We provide the following control surface functions in controller.py

```
 controller.collect_merge() ##collect results from all measurement points
 controller.query() ##check estimating value and report victims (that with high volume)
 controller.entropy() ##estimate the entropy
```

## 5. Configure flow keys

Flow keys and packet keys can be configured in measurement.p4 with following masks:

```
        bit<32> sip_mask_f = 0; 
        bit<32> dip_mask_f = 0xffffffff; //for estimating dest IP
        bit<16> sport_mask_f = 0;
        bit<16> dport_mask_f = 0;
        bit<8> protocol_mask_f = 0;

        bit<32> sip_mask = 0xffffffff;
        bit<32> dip_mask = 0xffffffff;
        bit<16> sport_mask = 0xffff;
        bit<16> dport_mask = 0xffff;
        bit<8> protocol_mask = 0xff;
        bit<16> ip_checksum_mask = 0xffff;
        bit<16> transport_checksum_mask = 0xffff;
        bit<16> payload_mask = 0xffff;
```

## 6. baselines and topologies

Replace the file in the `lemon_bmv2/` directory with corresponding `measurement.p4` and `p4app.json `from beselines and topologies.

## 7. Datasets

The background traffic comes from [MAWI Working Group Traffic Archive](https://mawi.wide.ad.jp/mawi/). The attack traffic generation tool can be found at `/controlplane/traffic_generation/`
