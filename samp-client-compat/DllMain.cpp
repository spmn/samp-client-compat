#include <Windows.h>
#include <Winsock2.h>

#include "urmem/urmem.hpp"
#include "RakNet/BitStream.h"
#include "RakNet/NetworkTypes.h"


urmem::hook Hook_CNetGame__Packet_ConnectionSucceeded;
std::vector<urmem::patch> CompatibilityPatches;
std::vector<urmem::hook> CompatibilityHooks;

DWORD hSAMPDll;

template <class... Args>
void CChatWindow__AddDebugMessage(const char* szFormat, Args&&... args);
void ToggleCompatHacks(bool toggle);
bool Is037Server(unsigned int binaryAddress, int port);

#define ADD_COMPAT_PATCH(samp_offset, ...) CompatibilityPatches.emplace_back(hSAMPDll + (samp_offset), urmem::bytearray_t(__VA_ARGS__))
#define ADD_COMPAT_CALLHOOK(samp_offset, ...) CompatibilityHooks.emplace_back(hSAMPDll + (samp_offset), urmem::get_func_addr(__VA_ARGS__), urmem::hook::type::call)


void __fastcall Hooked_CNetGame__Packet_ConnectionSucceeded(void *_this, void *_edx, Packet *packet)
{
    bool isCompat = Is037Server(packet->playerId.binaryAddress, packet->playerId.port);

    if (isCompat)
        CChatWindow__AddDebugMessage("Connecting as SA-MP 0.3.7 client...");

    ToggleCompatHacks(isCompat);
    Hook_CNetGame__Packet_ConnectionSucceeded.call<urmem::calling_convention::thiscall>(_this, packet);
}

template <int CustomSkinOffset>
bool __fastcall Hooked_BitStream__ReadArray(void* _this, void* _edx, char* output, unsigned int numberOfBytes)
{
    bool ret = urmem::call_function<urmem::calling_convention::thiscall, bool>(hSAMPDll + 0x1F960, _this, output, numberOfBytes - 4);

    memmove(output + CustomSkinOffset + 4, output + CustomSkinOffset, numberOfBytes - CustomSkinOffset - 4);
    *(DWORD *)(output + CustomSkinOffset) = 0;
    return ret;
}


void InstallCompatHacks()
{
    Hook_CNetGame__Packet_ConnectionSucceeded.install(hSAMPDll + 0xB083, urmem::get_func_addr(Hooked_CNetGame__Packet_ConnectionSucceeded), urmem::hook::type::call);

    ADD_COMPAT_PATCH(0xAB44,  { 0xD9, 0x0F }); // challenge xor    @ CNetGame__Packet_ConnectionSucceeded
    ADD_COMPAT_PATCH(0xABAE,  { 0xD9, 0x0F }); // netgame response @ CNetGame__Packet_ConnectionSucceeded
    ADD_COMPAT_PATCH(0x18D1A, { 0x20 });       // playerid size    @ ScrSetPlayerSkin (4byte on pre-0.3.DL)
    ADD_COMPAT_PATCH(0x18D37, { 0xEB, 0x10 }); // custom skin read @ ScrSetPlayerSkin
    ADD_COMPAT_PATCH(0x10A7A, { 0xEB, 0x10 }); // custom skin read @ WorldPlayerAdd

    // the parameters of the following RPCs are sent as a packed struct so I can't NOP individual read calls as above
    // instead I'll patch the BitStream::ReadArray function to read `sizeof(struct) - 4` bytes
    // then insert a 4byte ZERO at the offset where `custom skin id` field should be

    ADD_COMPAT_CALLHOOK(0xE9CE,  Hooked_BitStream__ReadArray<0x06>); // ShowActor
    ADD_COMPAT_CALLHOOK(0xFF1D,  Hooked_BitStream__ReadArray<0x05>); // RequestClass
    ADD_COMPAT_CALLHOOK(0x17AC3, Hooked_BitStream__ReadArray<0x05>); // ScrSetSpawnInfo

    ToggleCompatHacks(false);
}

void ToggleCompatHacks(bool toggle)
{
    for (auto& patch : CompatibilityPatches) {
        if (toggle)
            patch.enable();
        else
            patch.disable();
    }

    for (auto& hook : CompatibilityHooks) {
        if (toggle)
            hook.enable();
        else
            hook.disable();
    }
}

DWORD WINAPI MainThread(LPVOID)
{
    if (strstr(GetCommandLineA(), "-c") == nullptr)
        return 0; // process wasn't started by samp.exe

    while ((hSAMPDll = (DWORD)GetModuleHandleW(L"samp.dll")) == 0)
        Sleep(100);

    if (*(DWORD*)(hSAMPDll + 0xAB44) != 0x0FDE)
        return 0; // incompatible SA-MP version (0.3.DL only)

    InstallCompatHacks();
    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

// ---- helpers ---- //

template <class... Args>
void CChatWindow__AddDebugMessage(const char* szFormat, Args&&... args)
{
    void* _this = *(void**)(hSAMPDll + 0x2ACA10);

    if (_this)
        urmem::call_function(hSAMPDll + 0x67B60, _this, szFormat, std::forward<Args>(args)...);
}

bool Is037Server(unsigned int binaryAddress, int port)
{
    SOCKET s;
    sockaddr_in addr;
    DWORD timeout = 2000;
    int ret;
    char buffer[256];

    RakNet::BitStream bsSend;
    bsSend.Write<DWORD>('PMAS');
    bsSend.Write<DWORD>(binaryAddress);
    bsSend.Write<WORD>(port);
    bsSend.Write<CHAR>('r');

    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.S_un.S_addr = binaryAddress;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return 0;

    ret = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if (ret == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }

    ret = connect(s, (sockaddr*)&addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }

    ret = sendto(s, (char*)bsSend.GetData(), bsSend.GetNumberOfBytesUsed(), 0, (sockaddr*)&addr, sizeof(addr));
    if (ret != bsSend.GetNumberOfBytesUsed()) {
        closesocket(s);
        return 0;
    }

    ret = recvfrom(s, buffer, sizeof(buffer), 0, nullptr, nullptr);
    closesocket(s);

    if (ret < 11 + 2) // minimum SA-MP header size + 2 bytes for rule count
        return 0;

    RakNet::BitStream bsRecv((unsigned char*)buffer, ret, false);
    WORD ruleCount;
    BYTE ruleNameLen;
    CHAR ruleName[256];
    BYTE ruleValueLen;
    CHAR ruleValue[256];

    bsRecv.IgnoreBits(11 * 8);
    bsRecv.Read(ruleCount);
    for (int i = 0; i != ruleCount; ++i) {
        bsRecv.Read(ruleNameLen);
        bsRecv.Read(ruleName, ruleNameLen);
        bsRecv.Read(ruleValueLen);
        bsRecv.Read(ruleValue, ruleValueLen);

        ruleName[ruleNameLen] = 0;
        ruleValue[ruleValueLen] = 0;

        if (!strcmp(ruleName, "version"))
            return strstr(ruleValue, "0.3.7") != nullptr;
    }

    return 0;
}
