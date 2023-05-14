I have created a small sleep obfuscation technique using the Win32 API called `CreateTimerQueueTimer` that uses basic sleep timers.

```
BOOL CreateTimerQueueTimer(
  [out]          PHANDLE             phNewTimer,
  [in, optional] HANDLE              TimerQueue,
  [in]           WAITORTIMERCALLBACK Callback,
  [in, optional] PVOID               Parameter,
  [in]           DWORD               DueTime,
  [in]           DWORD               Period,
  [in]           ULONG               Flags
);
```


### Credits
I forked it so I would like to take this opportunity to thank you for giving me the chance to learn something new.
You might want to check my code as well if you see that :P

- [Austin Hudson (@SecIdiot)](https://twitter.com/ilove2pwn_)
- Originally discovered by [Peter Winter-Smith](peterwintrsmith) and used in MDSec’s Nighthawk
- https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer
