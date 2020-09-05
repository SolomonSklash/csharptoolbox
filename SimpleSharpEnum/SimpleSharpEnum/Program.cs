using System;
using System.Management;
using Microsoft.Win32;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Linq;


// SimpleSharpEnum
// Windows enumeration tool -- A project to get my feet wet with C# 
// 
// Gathers the following info:
// OS build and Version, computer architecture, memory
// Current running version of .NET
// Username, Domain, Current execution contest (elevated or not)
// Computer name, domain controllers
// Networking info: IP addresses, netmasks, gateways, DNS servers, static/DHCP
// Exported shares
// Local users, and whether they are admin or not
// Users who have profiles on the system
// Users currently logged on and idle times

namespace SimpleSharpEnum
{
    public class Program
    {
        [DllImport("kernel32")]
        extern static UInt64 GetTickCount64();
        [DllImport("kernel32")]
        private static extern bool GetPhysicallyInstalledSystemMemory(out long TotalMemoryInKilobytes);
        [DllImport("netapi32.dll", EntryPoint = "NetLocalGroupGetMembers")]
        internal static extern uint NetLocalGroupGetMembers();

        static void Main(string[] args)
        {
            Banner();
            Host();
            Process(args);
            Network();
            Users();
            Shares();
        }
        static void Banner()
        {
            // C# Here-string (contains newline chars)
            string Banner = @"                                                                                                                                             
             ,---.  ,--.                 ,--.        ,---.  ,--.                           ,------.                           
            '   .-' `--',--,--,--. ,---. |  | ,---. '   .-' |  ,---.  ,--,--.,--.--. ,---. |  .---',--,--, ,--.,--.,--,--,--. 
            `.  `-. ,--.|        || .-. ||  || .-. :`.  `-. |  .-.  |' ,-.  ||  .--'| .-. ||  `--, |      \|  ||  ||        | 
            .-'    ||  ||  |  |  || '-' '|  |\   --..-'    ||  | |  |\ '-'  ||  |   | '-' '|  `---.|  ||  |'  ''  '|  |  |  | 
            `-----' `--'`--`--`--'|  |-' `--' `----'`-----' `--' `--' `--`--'`--'   |  |-' `------'`--''--' `----' `--`--`--'                                                                                 
            ";
            Console.WriteLine(Banner);
        }
        private static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static void GetLocalAdmins()
        {
            SelectQuery sQuery = new SelectQuery("Win32_Group", "Name='Administrators'");

            try
            {
                ManagementObjectSearcher mSearcher = new ManagementObjectSearcher(sQuery);

                foreach (ManagementObject mObject in mSearcher.Get())
                {
                    foreach (ManagementObject relatedMObject in mObject.GetRelated())
                    {
                        foreach (PropertyData propData in relatedMObject.Properties)
                        {
                            if (propData.Name == "Caption")
                            {
                                Console.WriteLine(propData.Value);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        private static void QueryUser()
        {
            ManagementObjectSearcher query = new ManagementObjectSearcher("SELECT * FROM Win32_UserProfile WHERE Loaded = True");
            foreach (ManagementObject mObject in query.Get())
            {
                foreach (PropertyData propData in mObject.Properties)
                {
                    if (propData.Name == "SID")
                    {
                        string sid = propData.Value.ToString();
                        string account = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
                        Console.WriteLine(account);
                    }

                }
            }
        }
        static void Host()
        {
            OperatingSystem os = Environment.OSVersion;
            string releaseId = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "").ToString();
            string version = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion", "ProductName", null);
            TimeSpan uptime = TimeSpan.FromMilliseconds(GetTickCount64());
            GetPhysicallyInstalledSystemMemory(out long memKB);
            long memory = memKB / 1048576;

            Console.WriteLine("[*] Gathering host info");
            Console.WriteLine("=========================================================");
            Console.WriteLine("Hostname:" + "\t\t" + Dns.GetHostName());
            Console.WriteLine("Domain:" + "\t\t\t" + Environment.UserDomainName);
            Console.WriteLine("OS Version:" + "\t\t" + os.VersionString);
            Console.WriteLine("OS ProductName:" + "\t\t" + version);
            Console.WriteLine("OS ReleaseID:" + "\t\t" + releaseId);
            Console.WriteLine("OS Arch:" + "\t\t" + RuntimeInformation.OSArchitecture);
            Console.WriteLine("Total Memory:" + "\t\t" + memory + " GB");
            Console.WriteLine("System Clock:" + "\t\t" + DateTime.Now);
            Console.WriteLine("Host Uptime:" + "\t\t" + uptime.Days + " Day(s), " + uptime.Hours + " Hour(s), " + uptime.Minutes + " Minute(s)");
            Console.WriteLine("");
        }
        static void Process(string[] args)
        {
            var proc = System.Diagnostics.Process.GetCurrentProcess();

            Console.WriteLine("[*] Gathering info about the current process");
            Console.WriteLine("=========================================================");
            Console.WriteLine("Process Arch:" + "\t\t" + RuntimeInformation.ProcessArchitecture);
            Console.WriteLine("Process Name:" + "\t\t" + proc.ProcessName);
            Console.WriteLine("Process ID:" + "\t\t" + proc.Id);
            Console.WriteLine("Is Elevated:" + "\t\t" + IsHighIntegrity());
            Console.WriteLine("DotNET Version:" + "\t\t" + Environment.Version);
            Console.WriteLine("Current Dir:" + "\t\t" + Directory.GetCurrentDirectory());
            Console.WriteLine("Assembly Dir:" + "\t\t" + Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
            Console.WriteLine("Process Args:" + "\t\t" + string.Join(" ", args));
            Console.WriteLine("");
        }
        static void Network()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_NetworkAdapterConfiguration");

            Console.WriteLine("[*] Gathering info about network settings");
            Console.WriteLine("=========================================================");

            foreach (NetworkInterface iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties ifaceProps = iface.GetIPProperties();
                Console.WriteLine("Interface:" + "\t\t" + iface.Name);
                Console.WriteLine("---------------------------------------------------------");
                Console.WriteLine("Interface Status:" + "\t" + iface.OperationalStatus);

                foreach (UnicastIPAddressInformation address in ifaceProps.UnicastAddresses)
                {
                    if (address.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine("IP Addr/Netmask:" + "\t" + address.Address.ToString() + " / " + address.IPv4Mask.ToString());
                    }
                }
                foreach (GatewayIPAddressInformation address in ifaceProps.GatewayAddresses)
                {
                    Console.WriteLine("Gateway:" + "\t\t" + address.Address.ToString());
                }
                foreach (var address in ifaceProps.DnsAddresses)
                {
                    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine("DNS Server:" + "\t\t" + address.ToString());
                    }
                }
                if (ifaceProps.GetIPv4Properties().IsDhcpEnabled)
                {
                    Console.WriteLine("DHCP Enabled:" + "\t\t" + "True");
                    foreach (var address in ifaceProps.DhcpServerAddresses)
                    {
                        Console.WriteLine("DHCP Server:" + "\t\t" + address);
                    }
                }
                else
                {
                    Console.WriteLine("DHCP Enabled:" + "\t\t" + "False");
                }
                if (iface.GetPhysicalAddress().ToString() != "")
                {
                    Console.WriteLine("MAC Address:" + "\t\t" + iface.GetPhysicalAddress().ToString());
                }
                Console.WriteLine("");
            }
            foreach (ManagementObject queryObj in searcher.Get())
            {
                if (queryObj["TcpipNetbiosOptions"] != null)
                {
                    if ((UInt32)queryObj["TcpipNetbiosOptions"] == 0)
                    {
                        Console.WriteLine("NetBios:" + "\t\t" + "0: Default, so probably enabled");
                    }
                    else if ((UInt32)queryObj["TcpipNetbiosOptions"] == 1)
                    {
                        Console.WriteLine("NetBios:" + "\t\t" + "1: Enabled");
                    }
                    else if ((UInt32)queryObj["TcpipNetbiosOptions"] == 2)
                    {
                        Console.WriteLine("NetBios:" + "\t\t" + "2: Disabled");
                    }
                    else
                    {
                        Console.WriteLine("NetBios:" + "\t\t" + "Unknown ???");
                    }
                }
            }
            Console.WriteLine("");
        }
        static void Users()
        {
            ManagementObjectSearcher usersSearcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_UserAccount");
            ManagementObjectCollection users = usersSearcher.Get();

            var localUsers = users.Cast<ManagementObject>().Where(
                u => (bool)u["LocalAccount"] == true &&
                     int.Parse(u["SIDType"].ToString()) == 1 &&
                     u["Name"].ToString() != "HomeGroupUser$");

            string current_user = WindowsIdentity.GetCurrent().Name;

            Console.WriteLine("[*] Gathering info about users");
            Console.WriteLine("=========================================================");
            Console.WriteLine("Current User:" + "\t\t" + current_user);
            Console.WriteLine("");
            Console.WriteLine("Users logged in:");
            Console.WriteLine("---------------------------------------------------------");
            QueryUser();
            Console.WriteLine("");
            Console.WriteLine("Members of local admins group:");
            Console.WriteLine("---------------------------------------------------------");
            GetLocalAdmins();
            Console.WriteLine("");

            foreach (ManagementObject user in localUsers)
            {
                Console.WriteLine("Local user:" + "\t\t" + user["Caption"].ToString());
                Console.WriteLine("---------------------------------------------------------");
                Console.WriteLine("Description:" + "\t\t" + user["Description"].ToString());
                Console.WriteLine("Disabled:" + "\t\t" + user["Disabled"].ToString());
                Console.WriteLine("Domain:" + "\t\t\t" + user["Domain"].ToString());
                Console.WriteLine("Lockout:" + "\t\t" + user["Lockout"].ToString());
                Console.WriteLine("Name:" + "\t\t\t" + user["Name"].ToString());
                Console.WriteLine("Password Changeable:" + "\t" + user["PasswordChangeable"].ToString());
                Console.WriteLine("Password Expires:" + "\t" + user["PasswordExpires"].ToString());
                Console.WriteLine("Password Required:" + "\t" + user["PasswordRequired"].ToString());
                Console.WriteLine("SID:" + "\t\t\t" + user["SID"].ToString());
                Console.WriteLine("");
            }
        }
        static void Shares()
        {
            Console.WriteLine("[*] Gathering info about file shares");
            Console.WriteLine("=========================================================");
            ManagementObjectSearcher shareSearcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM Win32_Share");

            foreach (ManagementObject share in shareSearcher.Get())
            {
                string name = "";
                string desc = "";
                string path = "";
                foreach (PropertyData propData in share.Properties)
                {
                    if (propData.Name == "Description")
                    {
                        desc = (string)propData.Value;
                    }
                    if (propData.Name == "Name")
                    {
                        name = (string)propData.Value;
                    }
                    if (propData.Name == "Path")
                    {
                        path = (string)propData.Value;
                    }
                }
                Console.WriteLine("Share Name:" + "\t\t" + name);
                Console.WriteLine("---------------------------------------------------------");
                Console.WriteLine("Path:" + "\t\t\t" + path);
                Console.WriteLine("Description:" + "\t\t" + desc);
                Console.WriteLine("");
            }
        }
    }
}
