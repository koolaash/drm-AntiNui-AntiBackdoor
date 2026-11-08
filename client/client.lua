-- Drm Anti Nui & Anti Backdoor

local _SendNUIMessage = SendNUIMessage
local _TriggerServerEvent = TriggerServerEvent
local _RegisterNUICallback = RegisterNUICallback
local _RegisterNetEvent = RegisterNetEvent

_RegisterNUICallback('drm:nuiReady', function(data, cb)
    if cb then cb('ok') end
    local nuiToken = (type(data) == 'table' and data.nuiToken) and tostring(data.nuiToken) or ''
    _TriggerServerEvent('drm-scanner:server:nuiReady', nuiToken)
end)

_RegisterNUICallback('drm:nuiDevToolsDetected', function(data, cb)
    if cb then cb('ok') end
    local method = (type(data) == 'table' and data.method) and tostring(data.method) or 'unknown'
    _TriggerServerEvent('drm-scanner:server:nuiDevToolsDetected', method)
end)

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

_RegisterNetEvent('drm-scanner:client:sendChallenge', function(challengeId, token, salt, seq)
    _SendNUIMessage({
        action = 'drm:challengeHeartbeat',
        challengeId = challengeId,
        token = token,
        salt = salt,
        seq = seq
    })
end)

local playerReadyReported = false

local function markPlayerReady()
    if playerReadyReported then return end
    playerReadyReported = true
    _SendNUIMessage({ action = 'drm:requestNuiReady' })
    _TriggerServerEvent('drm-scanner:server:playerReady')
end

AddEventHandler('playerSpawned', function()
    markPlayerReady()
end)

AddEventHandler('esx:loadingScreenOff', function()
    markPlayerReady()
end)

RegisterNetEvent('QBCore:Client:OnPlayerLoaded', function()
    markPlayerReady()
end)
RegisterNetEvent('qb-multicharacter:client:chooseChar', function()
    markPlayerReady()
end)

CreateThread(function()
    while not NetworkIsPlayerActive(PlayerId()) do
        Wait(500)
    end
    -- Player has exited the loading screen and entered character select / game session
    Wait(2000)
    markPlayerReady()
end)

_RegisterNetEvent('drm-scanner:client:requestRehandshake', function()
    playerReadyReported = false
    _SendNUIMessage({ action = 'drm:requestNuiReady' })
    _TriggerServerEvent('drm-scanner:server:playerReady')
end)
