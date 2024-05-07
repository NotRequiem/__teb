Dynamic Link Library that can be injected into any process to read, parse and print the full undocumented user-mode TEB structure on Windows 11 23H2 into a new allocated console

Code running in user mode can readily locate the Thread Environment Block (TEB) associated with the current thread. When a thread with a TEB is operating in user mode, the fs register (for 32-bit code) or gs register (for 64-bit code) points to this TEB.

The TEB contains its own address conveniently stored in its NtTib.Self component. Accessing just this component using a segment-register override provides a linear address, enabling access to all other parts of the TEB without requiring overrides. 


The Thread Environment Block (TEB) of any thread can be located using a handle with adequate access rights. The key to accessing it is the NtQueryInformationThread function, which is exported by NTDLL in all known versions of Windows (though not as a kernel-mode export before version 5.1). When using this function, the ThreadBasicInformation (0x00) case provides details in a THREAD_BASIC_INFORMATION structure, including the TebBaseAddress member, which holds the TEB's address for the queried thread.

Another useful case of this function is ThreadDescriptorTableEntry (0x06), particularly on 32-bit Windows. Here, you can inquire about the KGDT_R3_TEB selector using the GetThreadSelectorEntry API function.

However, when dealing with a thread in another process, which is often the most practical scenario, the obtained address isn't directly applicable. It's relevant only within the other process's address space.

That's why I opted to create a dynamic link library (DLL) that triggers the macro mentioned earlier when it's loaded into a process's memory space. By doing this, the DLL obtains a pointer to the internal structure we discussed earlier. Then, it proceeds to read the memory containing all the undocumented fields.

