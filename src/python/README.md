# Python-Integration

`escape_component.py` ist eine lauffaehige Komponente: Sie startet einen
HTTP-Server, verarbeitet und publiziert HMAC-authentifizierte UDP-Broadcasts
und entschluesselt die geschuetzten Manager-POST-Endpunkte mit P-256, HKDF-SHA-256
und AES-256-GCM. Das Wire-Format entspricht `src/protocol/SecureTransport.cpp`.

```sh
python3 -m pip install -r src/python/requirements.txt
```

```python
from EscapeManager.src.python import EscapeComponent, PlanAction

component = EscapeComponent(host_name="laser-python", http_port=8080)
laser = component.add_component("Laser-1", "Raum-A")
component.on_actions(laser, lambda: ["reset"])
component.on_action(laser, lambda action: action == "reset")
component.on_plan_action(laser, lambda action: action is PlanAction.RESET)
component.begin()

try:
	while True:
		component.loop()
finally:
	component.close()
```

Der HTTP-Port muss fuer den Manager erreichbar sein. Port 80 braucht auf Linux
in der Regel besondere Rechte; fuer Tests kann ein anderer Port verwendet werden.
Die Runtime kuendigt standardmaessig ausserdem `escapemanager.local` per mDNS
an. Der Hostname kann ueber `mdns_hostname` angepasst oder mit
`mdns_enabled=False` deaktiviert werden.
