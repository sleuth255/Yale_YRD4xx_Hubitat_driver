/**
 * 	Yale Assure Lock 2 Hubitat Driver
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 *  Features:
 *  - Z-Wave S2 Security (Supervision encapsulation)
 *  - DoorSense (Contact Sensor)
 *  - Lock Code Manager compatibility
 *  - Detailed Event Text Reporting
 *
 *  Developed by Trunzoc.  Mods and fixes by Sleuth255. Development thread here:
 *  https://community.hubitat.com/t/adding-doorsense-to-z-wave-yale-driver
 *
 */

metadata {
    definition (name: "Yale Assure Lock 2", namespace: "Sleuth255", author: "Trunzoc") {
        capability "Actuator"
        capability "Lock"
        capability "Lock Codes"
        capability "ContactSensor"
        capability "Battery"
        capability "Configuration"
        capability "Refresh"

		fingerprint mfr:"0129", prod:"8104", model:"45D1", deviceJoinName: "Yale Assure Lock 2, YRD410" //YRD410-ZW3
		fingerprint mfr:"0129", prod:"8104", model:"45D2", deviceJoinName: "Yale Assure Lock 2, YRD420" //YRD420-ZW3
		fingerprint mfr:"0129", prod:"8104", model:"45D3", deviceJoinName: "Yale Assure Lock 2, YRD430" //YRD430-ZW3
		fingerprint mfr:"0129", prod:"8104", model:"45D5", deviceJoinName: "Yale Assure Lock 2, YRD450" //YRD450-ZW3
		fingerprint mfr:"0129", prod:"8107", model:"49D1", deviceJoinName: "Yale Assure Lock 2 Touch, YRD410" //YRD410-F-ZW3
		fingerprint mfr:"0129", prod:"8107", model:"49D2", deviceJoinName: "Yale Assure Lock 2 Touch, YRD420" //YRD420-F-ZW3
		fingerprint mfr:"0129", prod:"8107", model:"49D3", deviceJoinName: "Yale Assure Lock 2 Touch, YRD430" //YRD430-F-ZW3
		fingerprint mfr:"0129", prod:"8107", model:"49D5", deviceJoinName: "Yale Assure Lock 2 Touch, YRD450" //YRD450-F-ZW3
    }

    preferences {
        input name: "txtEnable", type: "bool", title: "Enable descriptionText logging", defaultValue: true
        input name: "debugEnable", type: "bool", title: "Enable debug logging", defaultValue: true
        input name: "traceEnable", type: "bool", title: "Enable trace logging", defaultValue: false
    }
}

import hubitat.zwave.commands.doorlockv1.*
import hubitat.zwave.commands.usercodev1.*
import hubitat.zwave.commands.notificationv3.*
import hubitat.zwave.commands.supervisionv1.*

// --- Core Z-Wave Parsing ---
def parse(String description) {
	if (traceEnable) log.trace "parse(String description): ${description}"
    def result = null
    def cmd = zwave.parse(description, [ 0x98: 1, 0x62: 1, 0x71: 3, 0x80: 1, 0x85: 2, 0x86: 1, 0x6C: 1 ])
    if (cmd) {
        result = zwaveEvent(cmd)
        if (debugEnable) log.debug "Parsed ${cmd} to ${result.inspect()}"
    }
    return result
}

// --- S2 Security Supervision Handler ---
def zwaveEvent(SupervisionGet cmd) {
	if (traceEnable) log.trace "zwaveEvent(SupervisionGet cmd): ${cmd}"
    if (debugEnable) log.debug "SupervisionGet: $cmd"
    def encapsulatedCommand = cmd.encapsulatedCommand(commandClassVersions)
    if (encapsulatedCommand) {
        zwaveEvent(encapsulatedCommand)
    }
    sendHubCommand(new hubitat.device.HubAction(zwaveSecureEncap(zwave.supervisionV1.supervisionReport(sessionID: cmd.sessionID, reserved: 0, moreStatusUpdates: false, status: 0xFF, duration: 0).format()), hubitat.device.Protocol.ZWAVE))
    return null
}

def zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
	if (traceEnable) log.trace "zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd): ${cmd}"
    def encapsulatedCommand = cmd.encapsulatedCommand([0x62: 1, 0x71: 3, 0x80: 1, 0x85: 2, 0x63: 1, 0x98: 1, 0x86: 1])
    if (encapsulatedCommand) {
        return zwaveEvent(encapsulatedCommand)
    }
}

// --- Lock Operation & State ---
def zwaveEvent(DoorLockOperationReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(DoorLockOperationReport cmd): ${cmd}"
    def map = [name: "lock"]
    if (cmd.doorLockMode == 0xFF) {
        map.value = "locked"
        map.descriptionText = "${device.displayName} was locked"
    } else {
        map.value = "unlocked"
        map.descriptionText = "${device.displayName} was unlocked"
    }
    if (txtEnable) log.info map.descriptionText
    sendEvent(map)
}

// --- Consolidated Event Reporting ---
def zwaveEvent(NotificationReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(NotificationReport cmd): ${cmd}"
  	if (debugEnable) log.debug cmd.event
  
    // Notification Type 0x06: Access Control
    if (cmd.notificationType == 0x06) {
        def map = [name: "lock", isStateChange: true]
        switch (cmd.event) {
            case 0x01: // Manual Lock
                map.value = "locked"
                map.descriptionText = "${device.displayName} was locked manually"
                break
            case 0x02: // Manual Unlock
                map.value = "unlocked"
                map.descriptionText = "${device.displayName} was unlocked manually"
                break
            case 0x03: // RF/App Lock
                map.value = "locked"
                map.descriptionText = "${device.displayName} was locked digitally"
                break
            case 0x04: // RF/App Unlock
                map.value = "unlocked"
                map.descriptionText = "${device.displayName} was unlocked digitally"
                break
            case 0x05: // Keypad Lock
                map.value = "locked"
                map.descriptionText = "${device.displayName} was locked via keypad"
                break
            case 0x06: // Keypad Unlock (With User Data)
                def slotId = cmd.eventParameter[2]
                def codeName = getCodeName(slotId)
                map.value = "unlocked"
                map.descriptionText = "${device.displayName} unlocked by ${codeName}"
				sendEvent(name: "lastCodeName", value: codeName)
				state.remove("lastCodeName")
                break
            case 0x0D: // Code Deleted
                def slotId = cmd.eventParameter[1]
                if (txtEnable) log.info "${device.displayName} deleting code ${slotId}..."
                executeCommand(zwaveSecureEncap(zwave.userCodeV1.userCodeGet(userIdentifier: slotId)))
                return
            case 0x0E: // Code Added/Changed
                def slotId = cmd.eventParameter[0]
                if (txtEnable) log.info "${device.displayName} syncing code ${slotId}..."
                executeCommand(zwaveSecureEncap(zwave.userCodeV1.userCodeGet(userIdentifier: slotId)))
                return
			case 22: // Door Opened
            	map.name = contact
				map.value = "open"
				map.descriptionText = "${device.displayName} was opened"
				if (txtEnable) log.info "${device.displayName} was opened"
				sendEvent(name: "contact", value: "open", descriptionText: "${device.displayName} was opened")
				break;
            case 23: // Door Closed
            	map.name = contact
				map.value = "closed"
				map.descriptionText = "${device.displayName} was closed"
				if (txtEnable) log.info "${device.displayName} was closed"
				sendEvent(name: "contact", value: "closed", descriptionText: "${device.displayName} was closed")
                break
        }
        if (map.value) sendEvent(map)
    }
}

// Fallback handler for older Yale Z-Wave reporting structures (RF/App/Manual)
def zwaveEvent(hubitat.zwave.commands.alarmv2.AlarmReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(hubitat.zwave.commands.alarmv2.AlarmReport cmd): ${cmd}"
    
    // Alarm Type 0x09: Access Control (Legacy/RF Events)
    if (cmd.alarmType == 0x09) {
        switch (cmd.alarmLevel) {
            case 0x01: // Manual Lock
            case 0x02: // Manual Unlock
            case 0x03: // RF Lock
            case 0x04: // RF Unlock
                def status = (cmd.alarmLevel % 2 != 0) ? "locked" : "unlocked"
                sendEvent(name: "lock", value: status, descriptionText: "${device.displayName} ${status} via ${cmd.alarmLevel > 2 ? 'App' : 'Manual'}")
                break
        }
    }
    // Handle DoorSense (if reported via AlarmReport)
    if (cmd.alarmType == 0x16 || cmd.alarmType == 23) {
        return handleDoorSenseReport(cmd)        
    }
}

// --- Lock Code Manager Integration ---
def zwaveEvent(UserCodeReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(UserCodeReport cmd): ${cmd}"
    def codePosition = cmd.userIdentifier.toString()
    def lockCodes = loadLockCodes()
    
    if (cmd.userIdStatus == UserCodeReport.USER_ID_STATUS_OCCUPIED) {
        def pin = cmd.userCode.toString()
        if (!lockCodes.containsKey(codePosition) || lockCodes[codePosition].code != pin) {
            lockCodes[codePosition] = [name: "User ${codePosition}", code: pin, status: "active"]
            sendEvent(name: "codeChanged", value: "${codePosition} updated", descriptionText: "Code position ${codePosition} updated", isStateChange: true)
        }
    } else {
        if (lockCodes.containsKey(codePosition)) {
            lockCodes.remove(codePosition)
            sendEvent(name: "codeChanged", value: "${codePosition} deleted", descriptionText: "Code position ${codePosition} deleted", isStateChange: true)
        }
    }
    updateLockCodes(lockCodes)
}

def setCode(codePosition, pin, codeName = null) {
	if (traceEnable) log.trace "setCode(codePosition, pin, codeName = null): ${codePosition}, ${pin}, ${codeName}"
    if (!codeName) codeName = "User ${codePosition}"
    def lockCodes = loadLockCodes()
    lockCodes[codePosition.toString()] = [name: codeName, code: pin.toString(), status: "active"]
    updateLockCodes(lockCodes)
    
    executeCommand(zwaveSecureEncap(zwave.userCodeV1.userCodeSet(userIdentifier: codePosition, userIdStatus: 1, userCode: pin)))
}

def deleteCode(codePosition) {
	if (traceEnable) log.trace "deleteCode(codePosition): ${codePosition}"
    executeCommand(zwaveSecureEncap(zwave.userCodeV1.userCodeSet(userIdentifier: codePosition, userIdStatus: 0)))
}

def getCodes() {
	if (traceEnable) log.trace "getCodes()"
    executeCommand(zwaveSecureEncap(zwave.userCodeV1.usersNumberGet()))
}

private getCodeName(slotId) {
	if (traceEnable) log.trace "getCodeName(slotId): ${slotId}"
    def codes = loadLockCodes()
    def entry = codes["${slotId}"] ?: codes[slotId]
    return entry?.name ?: "User ${slotId}"
}

private Map loadLockCodes() {
	if (traceEnable) log.trace "loadLockCodes()"
    def lockCodes = device.currentValue("lockCodes")
    def decrypted = decrypt(lockCodes) ?: lockCodes
    return parseJson(decrypted ?: "{}") ?: [:]
}

private void updateLockCodes(lockCodes) {
	if (traceEnable) log.trace "updateLockCodes(lockCodes): ${lockCodes}"
    def json = new groovy.json.JsonOutput().toJson(lockCodes)
    sendEvent(name: "lockCodes", value: json, displayed: false, descriptionText: "Lock codes updated")
}

def zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd): ${cmd}"
    // 0xFF (255) is Z-Wave's standard report for a low battery warning
    def percent = (cmd.batteryLevel == 0xFF) ? 1 : cmd.batteryLevel
    
    def descText = "${device.displayName} battery is ${percent}%"
    
    if (txtEnable) log.info descText
    
    sendEvent(
        name: "battery", 
        value: percent, 
        unit: "%", 
        descriptionText: descText,
        isStateChange: true
    )
}

// Catch-all for any other unhandled Z-Wave commands to prevent future MissingMethodExceptions
def zwaveEvent(hubitat.zwave.Command cmd) {
	if (traceEnable) log.trace "zwaveEvent(hubitat.zwave.Command cmd): ${cmd}"
    if (debugEnable) log.debug "Unhandled Z-Wave Command: $cmd"
}

def zwaveEvent(hubitat.zwave.commands.usercodev1.UsersNumberReport cmd) {
	if (traceEnable) log.trace "zwaveEvent(hubitat.zwave.commands.usercodev1.UsersNumberReport cmd): ${cmd}"
    if (debugEnable) log.debug "UsersNumberReport: lock supports ${cmd.supportedUsers} codes"
    
    // Update the maxCodes attribute so Lock Code Manager knows the limit
    //sendEvent(name: "maxCodes", value: cmd.supportedUsers, displayed: false)
    //for some reason cmd.supportedUsers is returning 255 while max codes supported are actually 250
    sendEvent(name: "maxCodes", value: 250, displayed: false)
}

// --- Actuator Commands ---
def lock() {
	if (traceEnable) log.trace "lock()"
    executeCommand(zwaveSecureEncap(zwave.doorLockV1.doorLockOperationSet(doorLockMode: DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_SECURED)))
}

def unlock() {
	if (traceEnable) log.trace "unlock()"
    executeCommand(zwaveSecureEncap(zwave.doorLockV1.doorLockOperationSet(doorLockMode: DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED)))
}

def refresh() {
	if (traceEnable) log.trace "refresh()"
    def cmds = []
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    cmds << zwaveSecureEncap(zwave.batteryV1.batteryGet())
    sendHubCommand(new hubitat.device.HubMultiAction(cmds, hubitat.device.Protocol.ZWAVE))
}

def configure() {
	if (traceEnable) log.trace "configure()"
    log.info "Configuring Association Groups..."
    // Group 1 is the Lifeline for Z-Wave locks, required to report events to the Hub
    def hubNode = zwaveHubNodeId
    def cmds = []
    cmds << zwaveSecureEncap(zwave.associationV1.associationSet(groupingIdentifier: 1, nodeId: hubNode))
    cmds << zwaveSecureEncap(zwave.associationV1.associationGet(groupingIdentifier: 1))
    
    // Also request a full refresh to align current states
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    
    sendHubCommand(new hubitat.device.HubMultiAction(cmds, hubitat.device.Protocol.ZWAVE))
    sendEvent(name: "maxCodes", value: 250, displayed: false)
}

private executeCommand(command) {
	if (traceEnable) log.trace "executeCommand(command): ${command}"
    sendHubCommand(new hubitat.device.HubAction(command, hubitat.device.Protocol.ZWAVE))
}
