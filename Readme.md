# Hunt-Weird-ImageLoads

This project was created to play with different IOCs caused by Imageload events.    
It leverages ETW to monitor for ImageLoad events and walks the callstack to identify some possible IOCs, such as:

- R(W)X page in callstack
- Stomped module in callstack
- Module proxying ( ntdll -> kernel32!LoadLibrary ) as described [here](https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c) or [here](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing)
- New thread dedicated to load a library

There are two sample programs for **module proxying** and **dedicated threads** in this repository.

![In action](/screens/1.png?raw=true)

## Conclusion

In my tests, I had a lot of false positives monitoring for private or module stomped pages in the callstack and this is probably not a valid IOC.    
However, it seems that both, **module proxying** and **dedicated threads** are quite abnormal, but see yourself.

## Usage

```
    --all activates all alerts
    --rx alerts on private rx regions in callstack
    --rwx alerts on private rwx regions in callstack
    --stomped alerts on stomped modules in callstack
    --proxy alerts on abnormal calls to kernel32!loadlibrary from ntdll
    --dedicatedthread alerts on thread with baseaddr on loadlibrary*
```        

## Credits

- [@rad9800](https://twitter.com/rad9800) [For an example implementation of LoadLibray via RtlQueueWorkItem](https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c)
- [@NinjaParanoid](https://twitter.com/NinjaParanoid) [For a super cool blogpost on this topic](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)