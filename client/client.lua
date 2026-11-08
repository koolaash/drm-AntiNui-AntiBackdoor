-- DRM Security - Client Bridge for NUI DevTools Detection & Challenge-Response Heartbeat

local _SendNUIMessage = SendNUIMessage
local _TriggerServerEvent = TriggerServerEvent
local _RegisterNUICallback = RegisterNUICallback
local _RegisterNetEvent = RegisterNetEvent

-- 1. Forward NUI Ready Handshake to Server
_RegisterNUICallback('drm:nuiReady', function(data, cb)
    if cb then cb('ok') end
    local nuiToken = (type(data) == 'table' and data.nuiToken) and tostring(data.nuiToken) or ''
    _TriggerServerEvent('drm-scanner:server:nuiReady', nuiToken)
end)

-- 2. Forward NUI DevTools Detection to Server
_RegisterNUICallback('drm:nuiDevToolsDetected', function(data, cb)
    if cb then cb('ok') end
    local method = (type(data) == 'table' and data.method) and tostring(data.method) or 'unknown'
    _TriggerServerEvent('drm-scanner:server:nuiDevToolsDetected', method)
end)

-- 3. Forward Signed NUI Heartbeat Response to Server with Sequence Counter & ChallengeId
_RegisterNUICallback('drm:nuiHeartbeatResponse', function(data, cb)
    if cb then cb('ok') end
    if type(data) == 'table' and data.token and data.signature and data.seq ~= nil then
        _TriggerServerEvent('drm-scanner:server:heartbeatResponse', {
            challengeId = data.challengeId and tostring(data.challengeId) or '',
            token = tostring(data.token),
            signature = tostring(data.signature),
            seq = tonumber(data.seq)
        })
    end
end)

-- 4. Receive Challenge from Server and Deliver to NUI
_RegisterNetEvent('drm-scanner:client:sendChallenge', function(challengeId, token, salt, seq)
    _SendNUIMessage({
        action = 'drm:challengeHeartbeat',
        challengeId = challengeId,
        token = token,
        salt = salt,
        seq = seq
    })
end)

-- 5. Inform Server when Player has Finished Loading Assets and Reached Character Menu / Game
local playerReadyReported = false

local function markPlayerReady()
    if playerReadyReported then return end
    playerReadyReported = true
    _SendNUIMessage({ action = 'drm:requestNuiReady' })
    _TriggerServerEvent('drm-scanner:server:playerReady')
end

-- Detection A: Standard spawnmanager spawn event
AddEventHandler('playerSpawned', function()
    markPlayerReady()
end)

-- Detection B: ESX loading screen off
AddEventHandler('esx:loadingScreenOff', function()
    markPlayerReady()
end)

-- Detection C: QBCore / QBX multicharacter or loaded
RegisterNetEvent('QBCore:Client:OnPlayerLoaded', function()
    markPlayerReady()
end)
RegisterNetEvent('qb-multicharacter:client:chooseChar', function()
    markPlayerReady()
end)

-- Detection D: Engine-level network active check (guaranteed fallback when loading screen ends)
CreateThread(function()
    while not NetworkIsPlayerActive(PlayerId()) do
        Wait(500)
    end
    -- Player has exited the loading screen and entered character select / game session
    Wait(2000)
    markPlayerReady()
end)

-- 6. Re-handshake handler when resource is started or restarted while player is already in-game
_RegisterNetEvent('drm-scanner:client:requestRehandshake', function()
    playerReadyReported = false
    _SendNUIMessage({ action = 'drm:requestNuiReady' })
    _TriggerServerEvent('drm-scanner:server:playerReady')
end)
