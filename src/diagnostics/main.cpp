#include <Arduino.h>
#include "SPIFFS.h"
#include "esp_partition.h"

static void printSpiffsReport() {
  const esp_partition_t* spiffsPartition =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);

  if (spiffsPartition == nullptr) {
    Serial.println("SPIFFS Partition:   nicht vorhanden");
    return;
  }

  Serial.printf("SPIFFS Partition:   %u bytes\n", static_cast<unsigned>(spiffsPartition->size));

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount:       fehlgeschlagen (Format-Initialisierung ebenfalls fehlgeschlagen)");
    return;
  }

  const size_t totalBytes = SPIFFS.totalBytes();
  const size_t usedBytes = SPIFFS.usedBytes();
  const size_t freeBytes = totalBytes - usedBytes;

  Serial.printf("SPIFFS Total:       %u bytes\n", static_cast<unsigned>(totalBytes));
  Serial.printf("SPIFFS Used:        %u bytes\n", static_cast<unsigned>(usedBytes));
  Serial.printf("SPIFFS Free:        %u bytes\n", static_cast<unsigned>(freeBytes));

  SPIFFS.end();
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n--- ESP32 Memory Report ---");

  // RAM
  Serial.printf("Free Heap:          %u bytes\n", ESP.getFreeHeap());
  Serial.printf("Largest Free Block: %u bytes\n", ESP.getMaxAllocHeap());
  Serial.printf("Min Ever Free Heap: %u bytes\n", ESP.getMinFreeHeap());

  // Flash
  Serial.printf("Flash Chip Size:    %u bytes\n", ESP.getFlashChipSize());
  Serial.printf("Sketch Size:        %u bytes\n", ESP.getSketchSize());
  Serial.printf("Free Sketch Space:  %u bytes\n", ESP.getFreeSketchSpace());

  // SPIFFS
  printSpiffsReport();

  Serial.println("---------------------------\n");
}

void loop() {
}