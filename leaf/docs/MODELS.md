# Models for Furcate leaf nodes

Every published number below names its source. "V" means measured by the vendor or the model's author; "3P" means measured by someone else. Numbers measured on our own development board are in [TEST-RESULTS.md](TEST-RESULTS.md).

## Classic ESP32 (development board: no PSRAM, about 330 KB internal RAM)

| Rank | Task | Model and runtime | Accuracy | Published latency | RAM / flash | Source |
|---|---|---|---|---|---|---|
| 1 | Person present or absent (Visual Wake Words) | MobileNetV1 0.25, 96x96 int8, TFLM + ESP-NN | about 80-86% on VWW (MLPerf Tiny target 80%) | 380 ms with ESP-NN, 4084 ms without (V) | model about 300 KB, arena about 100 KB | esp-tflite-micro 1.4.1 readme |
| 2 | Keyword spotting | DS-CNN / micro_speech int8, TFLM | MLPerf Tiny target 90% | 314 ms + 304 ms MFCC on ESP-EYE (3P) | about 97 KB RAM | arXiv 2212.03332 |
| 3 | Sensor anomaly detection | dense autoencoder (MLPerf Tiny AD) | target AUC 0.85 | not published for ESP32 | under 300 KB | arXiv 2106.07597 |
| 4 | Small-image classification | ResNet-8 CIFAR-10 int8 | target 85% | 191 ms on ESP-EYE (3P) | under 100 KB RAM | arXiv 2212.03332 |
| 5 | Object centroids | Edge Impulse FOMO 96x96 | per project | 0.65-1.66 s on ESP-EYE (3P) | about 240 KB RAM | Edge Impulse docs and public projects |

Face detection, pedestrian detection and YOLO are not realistic here. ESP-DL supports the classic ESP32 only with plain C operators, and its detection zoo targets S3 and P4.

## ESP32-P4 (production vision) and ESP32-S3

All numbers are V, from Espressif's model-zoo component pages.

| Task | Model | Input | S3 | P4 | Accuracy |
|---|---|---|---|---|---|
| Person present | TFLM + ESP-NN | 96x96 | 54 ms | 73 ms | as above |
| Face detection | espdet_pico | 224 | 124 ms | 47 ms | mAP50-95 0.504 |
| Pedestrian detection | pedestrian_detect pico | 224 | 118 ms | 56 ms | not published |
| COCO detection (80 classes) | YOLO11n int8 | 320 | about 1.3 s | about 0.32 s | mAP50-95 0.277 |
| COCO detection (80 classes) | YOLO11n int8 | 640 | about 5.5 s | about 1.4 s | 0.370 |

## Research advances that matter here

All of these were measured on STM32-class MCUs, not on ESP chips.

| Work | Result |
|---|---|
| MCUNetV2 (NeurIPS 2021) | Patch-based inference cuts peak memory 4-8x. VWW above 90% in 32 KB SRAM. |
| MCUNetV3 (NeurIPS 2022) | On-device training in 256 KB SRAM: fine-tune on local data without data leaving the device |
| MCUFormer (2023) | A vision transformer reaching 73.6% ImageNet top-1 in 320 KB |
| TinyissimoYOLO (2023) | 422k-parameter detector: 359 ms on a Cortex-M7 |
| XiNet (2024) | Detection with no external RAM, 57.9 mAP |
| AtomNet (AAAI 2025) | 66.7% ImageNet top-1 in 256 KB SRAM / 1 MB flash |
| ESP-DL 3.3 (2026) | w8a16 mixed precision; YOLO11n-640 on S3 fell from 26 s to 5.5 s across releases |

## The model used in phase 1

**Model.** The TFLite Micro person-detection model: MobileNetV1 0.25 trained on Visual Wake Words, 96x96x1 int8 input, two outputs (`no_person`, `person`).

- It comes from the `espressif/esp-tflite-micro` 1.4.1 component's example, so it is pinned and hash-recorded.
- It is published in the development registry as a release-signed artifact with a manifest.
- The self-test expectation is computed with the TFLite reference interpreter on the build host.

**Why this model.** It is the only model with a vendor-published classic-ESP32 latency (380 ms), so measuring it here checks a claim we rely on.
