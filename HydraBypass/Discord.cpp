#include "Discord.h"
#include <time.h>
#include <chrono>
static int64_t eptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();


void Discord::Initialize()
{
    DiscordEventHandlers Handle;
    memset(&Handle, 0, sizeof(Handle));
    Discord_Initialize("1093865001552461864", &Handle, 1, NULL); //Your Api Key
}

void Discord::Update()
{
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.state = "Discord: hanguyxn#7613";
    discordPresence.details = "Version: Vip 2.6.3";
    discordPresence.startTimestamp = time(0);
    discordPresence.largeImageKey = "hydra";
    discordPresence.largeImageText = "Hydra Bypass Safe For Main Account";
    discordPresence.smallImageKey = "tickk";
    Discord_UpdatePresence(&discordPresence);
}

