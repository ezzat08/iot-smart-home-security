// ================================================================
//  SECTION BRAIN — PHASE 1
//  Edge intelligence firmware for ESP32 security node
// ----------------------------------------------------------------
//  Responsibilities (Phase 1):
//    ✔ Read motion + vibration sensors with debounce
//    ✔ Apply cooldown between publishes (no spamming broker)
//    ✔ Build clean structured JSON payload
//    ✔ Local actuator response — buzzer + LED without waiting for
//      central brain MQTT round trip
//    ✔ Hold armed state locally — received once, acted on instantly
//    ✔ Publish own heartbeat every 30s to central brain
//    ✔ Monitor own nodes (sensors/actuators) via GPIO health check
//    ✔ Detect node anomalies — stuck HIGH, stuck LOW, abnormal
//      trigger frequency — report to central brain only on fault
//    ✔ Works standalone if MQTT drops (local response continues)
//
//  What this does NOT do (later phases):
//    ✗ Quarantine logic (Phase 6)
//    ✗ TLS / authentication (Phase 3)
//    ✗ DDoS detection (Phase 4)
//    ✗ Cross-section awareness (Central Brain responsibility)
//
//  Nodes:
//    Motion sensor   GPIO 13  — PIR
//    Vibration sensor GPIO 26  — SW-420 or similar
//    Buzzer          GPIO 32  — Active LOW
//    LED             GPIO 27  — Active HIGH
//
//  Topic structure:
//    Publish  → home/{SECTION}/status     sensor events
//    Publish  → home/{SECTION}/heartbeat  own heartbeat
//    Publish  → home/{SECTION}/fault      node fault alerts
//    Subscribe← home/{SECTION}/armed      armed state from central
//    Subscribe← home/{SECTION}/siren      siren override from central
// ================================================================
#define MBEDTLS_DEBUG_C
#define CONFIG_MBEDTLS_DEBUG_LEVEL 4

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "config.h"

// ----------------------------------------------------------------
//  PIN DEFINITIONS
// ----------------------------------------------------------------
#define PIN_MOTION      13
#define PIN_LED         27    // Active HIGH: HIGH = on
#define PIN_VIBRATION   26
#define PIN_BUZZER      32    // Active LOW: LOW = sound, HIGH = silent

// ----------------------------------------------------------------
//  TUNING PARAMETERS
// ----------------------------------------------------------------

// Debounce — how long a sensor must stay HIGH before confirming
#define DEBOUNCE_MOTION_MS      80    // PIR is hardware-latched, light debounce
#define DEBOUNCE_VIBRATION_MS   60    // Vibration is noisy, needs confirmation

// Cooldown — minimum gap between publishes for the same sensor
// Prevents flooding broker when sensor stays active
#define COOLDOWN_MOTION_MS      8000
#define COOLDOWN_VIBRATION_MS   5000

// Node health — thresholds for anomaly detection
#define STUCK_HIGH_MS           10000UL   // 5 min stuck HIGH = fault
#define STUCK_LOW_MS            3600000UL  // 1 hr stuck LOW = possibly dead
#define FREQ_WINDOW_MS          60000UL    // Frequency check window (1 min)
#define FREQ_MAX_TRIGGERS       20         // Max triggers per window before alert

// Heartbeat interval
#define HEARTBEAT_INTERVAL_MS   30000UL    // 30 seconds

// Siren pattern
#define SIREN_FREQ_HIGH         1200
#define SIREN_FREQ_LOW          750
#define SIREN_PHASE_HIGH_MS     400UL
#define SIREN_PHASE_LOW_MS      600UL

// LED strobe
#define LED_BLINK_MS            150UL

// ----------------------------------------------------------------
//  DYNAMIC TOPICS — built in setup() from SECTION_NAME
// ----------------------------------------------------------------
String TOPIC_STATUS;      // home/Yard/status
String TOPIC_HEARTBEAT;   // home/Yard/heartbeat
String TOPIC_FAULT;       // home/Yard/fault
String TOPIC_ARMED;       // home/Yard/armed
String TOPIC_SIREN;       // home/Yard/siren

// ----------------------------------------------------------------
//  NODE STATE STRUCT
//  Tracks full lifecycle of one physical sensor node
// ----------------------------------------------------------------
struct NodeState {
  const char* name;            // Human-readable label for fault reports
  int         pin;             // GPIO pin

  // Debounce
  bool          rawCurrent;    // Latest raw digitalRead
  bool          confirmed;     // Debounced confirmed state
  unsigned long debounceStart; // When raw went HIGH (start of debounce window)
  bool          debouncing;    // Waiting for debounce confirmation

  // Edge detection (post-debounce)
  bool          lastConfirmed; // Previous confirmed state

  // Cooldown — suppress re-publish while sensor is still hot
  unsigned long lastPublishMs;

  // Health monitoring
  unsigned long wentHighAt;    // Millis when node first went HIGH
  unsigned long wentLowAt;     // Millis when node first went LOW
  bool          stuckHighFault;
  bool          stuckLowFault;

  // Frequency tracking (abnormal trigger rate detection)
  int           triggerCount;
  unsigned long freqWindowStart;
  bool          freqFault;
};

// ----------------------------------------------------------------
//  GLOBAL STATE
// ----------------------------------------------------------------
NodeState motionNode    = { "PIR Motion",    PIN_MOTION,    false, false, 0, false, false, 0, 0, 0, false, false, 0, 0, false };
NodeState vibrationNode = { "Vibration",     PIN_VIBRATION, false, false, 0, false, false, 0, 0, 0, false, false, 0, 0, false };

bool          localArmed   = false;    // Held locally — updated via MQTT
bool          alarmActive  = false;    // Buzzer + LED running
bool          mqttWasLost  = false;    // Track reconnection for state republish

// Siren non-blocking state
int           sirenPhase   = 0;
unsigned long sirenTimer   = 0;

// LED strobe non-blocking state
bool          ledState     = false;
unsigned long ledTimer     = 0;

// Heartbeat timing
unsigned long lastHeartbeat = 0;

// Uptime counter (seconds, for heartbeat payload)
unsigned long uptimeSeconds = 0;
unsigned long lastUptimeTick = 0;

// ----------------------------------------------------------------
//  MQTT + WIFI OBJECTS
// ----------------------------------------------------------------
WiFiClientSecure   espClient;
PubSubClient mqtt(espClient);

// ================================================================
//  SETUP
// ================================================================
void setup() {
  Serial.begin(115200);
  Serial.println("\n[BOOT] Section Brain starting...");

  // Build all topics from SECTION_NAME
  buildTopics();

  // Safe output states BEFORE direction — prevents boot glitch
  pinMode(PIN_BUZZER, OUTPUT);  digitalWrite(PIN_BUZZER, HIGH);
  pinMode(PIN_LED,    OUTPUT);  digitalWrite(PIN_LED,    LOW);

  // Inputs
  pinMode(PIN_MOTION,    INPUT);
  pinMode(PIN_VIBRATION, INPUT);

  // Initialise node health timestamps
  unsigned long now = millis();
  motionNode.wentLowAt    = now;
  vibrationNode.wentLowAt = now;

  
  Serial.println("[TLS] CA Serial + dates:");
  Serial.println(String(CA_CERT));

  esp_log_level_set("mbedtls", ESP_LOG_VERBOSE);
  connectWiFi();

  Serial.printf("[HEAP] Free heap before TLS: %d bytes\n", ESP.getFreeHeap());
  espClient.setCACert(CA_CERT);
  espClient.setCertificate(CLIENT_CERT);
  espClient.setPrivateKey(CLIENT_KEY);
  Serial.println("[TLS] Certificates loaded");
  Serial.println("[TLS] CA cert first 40 chars:");
  Serial.println(String(CA_CERT).substring(0, 40));

  mqtt.setBufferSize(512);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMqttMessage);
  reconnectMQTT();

  lastHeartbeat  = millis();
  lastUptimeTick = millis();

  Serial.printf("[BOOT] %s online.\n", SECTION_NAME);
  printTopics();
}

// ================================================================
//  MAIN LOOP
// ================================================================
void loop() {
  unsigned long now = millis();

  // --- CONNECTIVITY ---
  if (!mqtt.connected()) {
    mqttWasLost = true;
    reconnectMQTT();
  }
  mqtt.loop();

  // Republish state after reconnection so central brain is current
  if (mqttWasLost && mqtt.connected()) {
    mqttWasLost = false;
    publishHeartbeat();
    Serial.println("[MQTT] Reconnected — state republished.");
  }

  // --- UPTIME TICK ---
  if (now - lastUptimeTick >= 1000) {
    uptimeSeconds++;
    lastUptimeTick = now;
  }

  // --- SENSOR PROCESSING ---
  processSensor(motionNode,    "pir",       "!! Motion Detected !!");
  processSensor(vibrationNode, "vibration", "!! Vibration Detected !!");

  // --- NODE HEALTH CHECKS ---
  checkNodeHealth(motionNode);
  checkNodeHealth(vibrationNode);

  // --- ALARM OUTPUTS ---
  if (alarmActive) {
    runSiren();
    runLedStrobe();
  } else {
    silenceBuzzer();
    digitalWrite(PIN_LED, LOW);
    ledState = false;
  }

  // --- HEARTBEAT ---
  if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
    publishHeartbeat();
    lastHeartbeat = now;
  }
}

// ================================================================
//  BUILD TOPICS
// ================================================================
void buildTopics() {
  String s = String(SECTION_NAME);
  TOPIC_STATUS    = "home/" + s + "/status";
  TOPIC_HEARTBEAT = "home/" + s + "/heartbeat";
  TOPIC_FAULT     = "home/" + s + "/fault";
  TOPIC_ARMED     = "home/" + s + "/armed";
  TOPIC_SIREN     = "home/" + s + "/siren";
}

void printTopics() {
  Serial.printf("[TOPICS] Pub status    : %s\n", TOPIC_STATUS.c_str());
  Serial.printf("[TOPICS] Pub heartbeat : %s\n", TOPIC_HEARTBEAT.c_str());
  Serial.printf("[TOPICS] Pub fault     : %s\n", TOPIC_FAULT.c_str());
  Serial.printf("[TOPICS] Sub armed     : %s\n", TOPIC_ARMED.c_str());
  Serial.printf("[TOPICS] Sub siren     : %s\n", TOPIC_SIREN.c_str());
}

// ================================================================
//  SENSOR PROCESSING
//  Full pipeline: raw read → debounce → cooldown → edge detect
//  → local actuator response → publish
// ================================================================
void processSensor(NodeState &node, const char* type, const char* alertMsg) {
  unsigned long now     = millis();
  bool          rawRead = digitalRead(node.pin);

  // ── STEP 1: DEBOUNCE ────────────────────────────────────────
  // Raw must stay HIGH continuously for DEBOUNCE_MS before confirming
  if (rawRead && !node.debouncing) {
    // First time we see HIGH — start debounce window
    node.debouncing    = true;
    node.debounceStart = now;
  } else if (!rawRead && node.debouncing) {
    // Went LOW before debounce window elapsed — noise, reset
    node.debouncing = false;
  }

  // Determine debounce threshold for this node
  unsigned long debounceMs = (strcmp(type, "pir") == 0)
      ? DEBOUNCE_MOTION_MS
      : DEBOUNCE_VIBRATION_MS;

  // Confirm only after debounce window elapses while still HIGH
  if (node.debouncing && rawRead && (now - node.debounceStart >= debounceMs)) {
    node.confirmed  = true;
    node.debouncing = false;
  } else if (!rawRead) {
    node.confirmed = false;
  }

  // ── STEP 2: HEALTH TIMESTAMP TRACKING ──────────────────────
  if (node.confirmed && !node.lastConfirmed) {
    // Rising edge — node just went HIGH
    node.wentHighAt     = now;
    node.stuckLowFault  = false;   // Was alive — clear stuck LOW fault

    // Frequency tracking
    if (now - node.freqWindowStart >= FREQ_WINDOW_MS) {
      node.freqWindowStart = now;
      node.triggerCount    = 0;
    }
    node.triggerCount++;
  } else if (!node.confirmed && node.lastConfirmed) {
    // Falling edge — node just went LOW
    node.wentLowAt      = now;
    node.stuckHighFault = false;   // Recovered — clear stuck HIGH fault
  }

  // ── STEP 3: EDGE DETECT + COOLDOWN ─────────────────────────
  unsigned long cooldownMs = (strcmp(type, "pir") == 0)
      ? COOLDOWN_MOTION_MS
      : COOLDOWN_VIBRATION_MS;

  bool risingEdge  = (node.confirmed && !node.lastConfirmed);
  bool fallingEdge = (!node.confirmed && node.lastConfirmed);

  node.lastConfirmed = node.confirmed;

  // ── STEP 4: PUBLISH + LOCAL RESPONSE ────────────────────────
  if (risingEdge) {
    bool cooldownElapsed = (now - node.lastPublishMs >= cooldownMs);

    if (cooldownElapsed) {
      node.lastPublishMs = now;

      // ── LOCAL ACTUATOR RESPONSE — no MQTT round trip needed ──
      // If armed, buzzer + LED activate HERE, right now
      if (localArmed && !alarmActive) {
        alarmActive = true;
        sirenPhase  = 0;
        sirenTimer  = now;
        tone(PIN_BUZZER, SIREN_FREQ_HIGH);
        Serial.printf("[ALARM] Local response — %s triggered\n", node.name);
      }

      // Publish clean event to central brain
      publishSensorEvent(type, alertMsg);

    } else {
      // Cooldown active — suppress publish but still respond locally
      Serial.printf("[COOLDOWN] %s suppressed (%.1fs remaining)\n",
                    node.name,
                    (cooldownMs - (now - node.lastPublishMs)) / 1000.0);

      // Still activate alarm locally if armed (even during cooldown)
      if (localArmed && !alarmActive) {
        alarmActive = true;
        sirenPhase  = 0;
        sirenTimer  = now;
        tone(PIN_BUZZER, SIREN_FREQ_HIGH);
      }
    }
  }

  if (fallingEdge) {
    // Sensor returned to idle — publish Secure
    // Central brain uses this to know the physical state
    // (dashboard sticky warning is handled by central brain, not here)
    publishSensorEvent(type, "Secure");
  }
}

// ================================================================
//  NODE HEALTH CHECK
//  Called every loop — detects stuck and abnormal frequency
//  Reports to central brain only when a fault is first detected
// ================================================================
void checkNodeHealth(NodeState &node) {
  unsigned long now = millis();

  // ── STUCK HIGH ──────────────────────────────────────────────
  // Node has been continuously HIGH beyond threshold
  if (node.confirmed && !node.stuckHighFault) {
    if ((now - node.wentHighAt) >= STUCK_HIGH_MS) {
      node.stuckHighFault = true;
      publishFault(node.name, "stuck_high",
                   "Sensor has been HIGH for over 5 minutes — possible fault or tamper");
      Serial.printf("[FAULT] %s stuck HIGH\n", node.name);
    }
  }

  // ── STUCK LOW ───────────────────────────────────────────────
  // Node has been continuously LOW far beyond normal — possibly dead
  if (!node.confirmed && !node.stuckLowFault) {
    if ((now - node.wentLowAt) >= STUCK_LOW_MS) {
      node.stuckLowFault = true;
      publishFault(node.name, "stuck_low",
                   "Sensor has not triggered in over 1 hour — possibly offline or disconnected");
      Serial.printf("[FAULT] %s stuck LOW (possibly dead)\n", node.name);
    }
  }

  // ── ABNORMAL FREQUENCY ──────────────────────────────────────
  // Too many triggers within the frequency window — possible sensor noise
  // or deliberate interference
  if (!node.freqFault && node.triggerCount >= FREQ_MAX_TRIGGERS) {
    if ((now - node.freqWindowStart) <= FREQ_WINDOW_MS) {
      node.freqFault = true;
      publishFault(node.name, "abnormal_frequency",
                   "Trigger count exceeded threshold within 1 minute — possible noise or attack");
      Serial.printf("[FAULT] %s abnormal trigger frequency (%d triggers)\n",
                    node.name, node.triggerCount);
    }
  }

  // Reset frequency fault flag when window resets
  if ((now - node.freqWindowStart) >= FREQ_WINDOW_MS) {
    node.freqFault      = false;
    node.triggerCount   = 0;
    node.freqWindowStart = now;
  }
}

// ================================================================
//  NON-BLOCKING SIREN  (tone-based wee-woo)
// ================================================================
void runSiren() {
  unsigned long now = millis();
  unsigned long duration = (sirenPhase == 0) ? SIREN_PHASE_HIGH_MS : SIREN_PHASE_LOW_MS;

  if (now - sirenTimer >= duration) {
    sirenPhase = 1 - sirenPhase;
    sirenTimer = now;
    tone(PIN_BUZZER, sirenPhase == 0 ? SIREN_FREQ_HIGH : SIREN_FREQ_LOW);
  }
}

void silenceBuzzer() {
  noTone(PIN_BUZZER);
  digitalWrite(PIN_BUZZER, HIGH);
}

// ================================================================
//  NON-BLOCKING LED STROBE
// ================================================================
void runLedStrobe() {
  unsigned long now = millis();
  if (now - ledTimer >= LED_BLINK_MS) {
    ledState = !ledState;
    digitalWrite(PIN_LED, ledState ? HIGH : LOW);
    ledTimer = now;
  }
}

// ================================================================
//  PUBLISH — SENSOR EVENT
//  Clean structured JSON — only meaningful fields
// ================================================================
void publishSensorEvent(const char* type, const char* status) {
  StaticJsonDocument<256> doc;
  doc["location"] = SECTION_NAME;
  doc["type"]     = type;
  doc["status"]   = status;
  doc["armed"]    = localArmed;   // Central brain knows context of event
  doc["uptime"]   = uptimeSeconds;

  char buf[256];
  serializeJson(doc, buf);
  mqtt.publish(TOPIC_STATUS.c_str(), buf);

  Serial.printf("[PUBLISH] %s | %s | %s\n", SECTION_NAME, type, status);
}

// ================================================================
//  PUBLISH — HEARTBEAT
//  Own health status — sent periodically
//  Central brain watchdog reads this to confirm section is alive
// ================================================================
void publishHeartbeat() {
  StaticJsonDocument<256> doc;
  doc["location"] = SECTION_NAME;
  doc["status"]   = "online";
  doc["armed"]    = localArmed;
  doc["alarm"]    = alarmActive;
  doc["uptime"]   = uptimeSeconds;
  doc["rssi"]     = WiFi.RSSI();   // WiFi signal strength — useful diagnostics

  // Summarise node health inline — no flood, just current state
  JsonObject nodes = doc.createNestedObject("nodes");
  nodes["pir"]       = motionNode.confirmed    ? "active"   : "idle";
  nodes["vibration"] = vibrationNode.confirmed ? "active"   : "idle";
  nodes["pir_fault"]       = (motionNode.stuckHighFault    || motionNode.stuckLowFault    || motionNode.freqFault);
  nodes["vibration_fault"] = (vibrationNode.stuckHighFault || vibrationNode.stuckLowFault || vibrationNode.freqFault);

  char buf[256];
  serializeJson(doc, buf);
  mqtt.publish(TOPIC_HEARTBEAT.c_str(), buf);

  Serial.printf("[HEARTBEAT] uptime=%lus rssi=%ddBm armed=%s alarm=%s\n",
                uptimeSeconds, WiFi.RSSI(),
                localArmed  ? "YES" : "NO",
                alarmActive ? "YES" : "NO");
}

// ================================================================
//  PUBLISH — FAULT REPORT
//  Only sent when a node anomaly is first detected
//  Central brain can log this and alert user
// ================================================================
void publishFault(const char* nodeName, const char* faultType, const char* detail) {
  StaticJsonDocument<256> doc;
  doc["location"]  = SECTION_NAME;
  doc["node"]      = nodeName;
  doc["fault"]     = faultType;
  doc["detail"]    = detail;
  doc["uptime"]    = uptimeSeconds;

  char buf[256];
  serializeJson(doc, buf);
  mqtt.publish(TOPIC_FAULT.c_str(), buf);

  Serial.printf("[FAULT REPORT] node=%s fault=%s\n", nodeName, faultType);
}

// ================================================================
//  MQTT RECEIVE CALLBACK
// ================================================================
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  String msg = "";
  for (unsigned int i = 0; i < length; i++) msg += (char)payload[i];
  String t = String(topic);

  // ── ARMED STATE ─────────────────────────────────────────────
  // Central brain tells this section to arm or disarm
  if (t == TOPIC_ARMED) {
    bool newArmed = (msg == "ON" || msg == "true" || msg == "1");

    if (newArmed != localArmed) {
      localArmed = newArmed;

      if (!localArmed) {
        // Disarmed — stop alarm locally immediately
        alarmActive = false;
        silenceBuzzer();
        digitalWrite(PIN_LED, LOW);
      }

      Serial.printf("[ARMED] Local state → %s\n", localArmed ? "ARMED" : "DISARMED");
    }
  }

  // ── SIREN OVERRIDE ──────────────────────────────────────────
  // Central brain can force siren ON or OFF directly
  // (e.g. coordinated multi-section alarm, or override during quarantine)
  if (t == TOPIC_SIREN) {
    if (msg == "ON") {
      alarmActive = true;
      sirenPhase  = 0;
      sirenTimer  = millis();
      tone(PIN_BUZZER, SIREN_FREQ_HIGH);
      Serial.println("[SIREN] Override ON from central brain");

    } else if (msg == "OFF") {
      alarmActive = false;
      silenceBuzzer();
      digitalWrite(PIN_LED, LOW);
      ledState = false;
      Serial.println("[SIREN] Override OFF from central brain");
    }
  }
}

// ================================================================
//  WIFI
// ================================================================
void connectWiFi() {
  Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\n[WiFi] Connected — IP: %s  RSSI: %ddBm\n",
                WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

// ================================================================
//  MQTT RECONNECT
//  Non-blocking in spirit — does retry but ESP32 can still run
//  locally between attempts (alarm stays active)
// ================================================================
void reconnectMQTT() {
  int attempts = 0;
  while (!mqtt.connected() && attempts < 5) {
    Serial.printf("[MQTT] Connecting with TLS (attempt %d)...", attempts + 1);

    String clientId = "SectionBrain_" + String(SECTION_NAME);
    clientId.replace(" ", "_");

    if (mqtt.connect(clientId.c_str())) {
      mqtt.subscribe(TOPIC_ARMED.c_str());
      mqtt.subscribe(TOPIC_SIREN.c_str());
      Serial.println(" Connected.");
      Serial.printf("[MQTT] Subscribed to %s\n", TOPIC_ARMED.c_str());
      Serial.printf("[MQTT] Subscribed to %s\n", TOPIC_SIREN.c_str());
    } else {
      Serial.printf(" Failed (rc=%d). Retry in 5s\n", mqtt.state());
      // Local alarm continues running during this delay
      // because reconnect is called from loop(), not blocking the
      // alarm output pins
      delay(5000);
      attempts++;
    }
  }

  if (!mqtt.connected()) {
    Serial.println("[MQTT] Could not connect after 5 attempts.");
    Serial.println("[MQTT] Running in standalone mode — local response active.");
  }
}
