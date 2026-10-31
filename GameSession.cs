using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MM2Trainer;

internal static class Native
{
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;

    public const uint MEM_COMMIT = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;   // aligned to 8 on x64 -> matches Win10+ layout
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, [Out] byte[] buf, IntPtr size, out IntPtr read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    public const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W pe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W pe);

    public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder name, ref int size);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassNameW(IntPtr hWnd, StringBuilder name, int count);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder text, int count);
}

/// <summary>Offsets reverse-engineered from GameAssembly.dll / global-metadata.dat (build 1.0.0, IL2CPP v29).</summary>
internal static class Off
{
    public const int AppData_Save = 0xA8;          // MySecureProperty save_
    public const int MySecure_Prop = 0x08;         // SecureProperty secureProperty_
    public const int SecureProp_Ints = 0x10;       // SecureInt[]
    public const int SecureProp_Lngs = 0x14;       // SecureLong[]
    public const int Arr_MaxLength = 0x0C;
    public const int Arr_Data = 0x10;
    public const int SecureNum_Bitmask = 0x08;
    public const int SecureNum_Original = 0x10;
    public const int SecureNum_Value = 0x18;

    public const int Klass_Name = 0x08;
    public const int Klass_Namespace = 0x0C;
    public const int Klass_StaticFields = 0x5C;

    public const int Idx_Money = 0;    // AppData.SAVEL.MONEY
    public const int Idx_Heart = 8;    // AppData.SAVEI.HEART
    public const int Idx_DPoint = 9;   // AppData.SAVEI.DPOINT  (in-game "P" coin)
}

internal sealed class GameSession : IDisposable
{
    public int Pid { get; private set; }
    public ulong Instance { get; private set; }
    public ulong Klass { get; private set; }
    public bool Attached => handle != IntPtr.Zero;
    public string LastError { get; private set; } = "";

    IntPtr handle = IntPtr.Zero;

    public struct Values
    {
        public long Money;
        public int Heart;
        public int DPoint;
        public bool Valid;
    }

    static IntPtr P(ulong a) => (IntPtr)(long)a;

    public bool ReadBytes(ulong addr, byte[] buf)
    {
        if (!Attached || addr < 0x10000) return false;
        bool ok = Native.ReadProcessMemory(handle, P(addr), buf, (IntPtr)buf.Length, out IntPtr got);
        return ok && (long)got == buf.Length;
    }

    public bool WriteBytes(ulong addr, byte[] buf)
    {
        if (!Attached) return false;
        bool ok = Native.WriteProcessMemory(handle, P(addr), buf, (IntPtr)buf.Length, out IntPtr got);
        return ok && (long)got == buf.Length;
    }

    public bool ReadU32(ulong addr, out uint v)
    {
        var b = new byte[4];
        v = 0;
        if (!ReadBytes(addr, b)) return false;
        v = BitConverter.ToUInt32(b, 0);
        return true;
    }

    static uint U32At(byte[] b, int off) => BitConverter.ToUInt32(b, off);
    static ulong U64At(byte[] b, int off) => BitConverter.ToUInt64(b, off);

    // ---------------------------------------------------------------- attach

    public static Process FindGameProcess()
    {
        // Process.GetProcessesByName() is filtered on some hardened hosts, so use a
        // plain toolhelp snapshot (same enumeration WOW64 tasks work with).
        int pid = FindGamePid();
        if (pid == 0) return null;
        try { return Process.GetProcessById(pid); }
        catch { return null; }
    }

    public static int FindGamePid()
    {
        int pid = FindViaToolhelp();
        if (pid != 0) return pid;
        return FindViaWindows();          // works even when process enumeration is filtered
    }

    static int FindViaToolhelp()
    {
        IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return 0;
        try
        {
            var pe = new Native.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32W>() };
            if (!Native.Process32FirstW(snap, ref pe)) return 0;
            int fallback = 0;
            do
            {
                string name = pe.szExeFile ?? "";
                if (!name.Equals("KairoGames.exe", StringComparison.OrdinalIgnoreCase)) continue;
                int pid = (int)pe.th32ProcessID;
                if (pid == 0) continue;
                try
                {
                    var p = Process.GetProcessById(pid);
                    if (p.MainWindowHandle != IntPtr.Zero) return pid;
                }
                catch { }
                if (fallback == 0) fallback = pid;
            } while (Native.Process32NextW(snap, ref pe));
            return fallback;
        }
        finally { Native.CloseHandle(snap); }
    }

    /// <summary>Walk top level windows and keep the one whose process image is KairoGames.exe.</summary>
    static int FindViaWindows()
    {
        int found = 0;
        var title = new StringBuilder(256);
        var cls = new StringBuilder(256);
        Native.EnumWindows((hWnd, _) =>
        {
            if (!Native.IsWindowVisible(hWnd)) return true;
            Native.GetWindowThreadProcessId(hWnd, out uint pid);
            if (pid == 0) return true;
            string image = ImageNameOf((int)pid);
            if (image == null) return true;
            if (!image.Equals("KairoGames.exe", StringComparison.OrdinalIgnoreCase)) return true;

            Native.GetClassNameW(hWnd, cls, cls.Capacity);
            Native.GetWindowTextW(hWnd, title, title.Capacity);
            // prefer the real game window (Unity player window) over helper windows
            if (found == 0 || cls.ToString().Contains("Unity", StringComparison.OrdinalIgnoreCase))
                found = (int)pid;
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static string ImageNameOf(int pid)
    {
        IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (!Native.QueryFullProcessImageNameW(h, 0, sb, ref size)) return null;
            return Path.GetFileName(sb.ToString());
        }
        finally { Native.CloseHandle(h); }
    }

    /// <summary>Attach to the running game and locate the AppData singleton. Returns false with a reason.</summary>
    public bool Attach(out string message, int pidOverride = 0)
    {
        Detach();
        int pid = pidOverride;
        if (pid == 0) pid = FindGamePid();
        if (pid == 0) { message = "没有找到游戏进程（KairoGames.exe），请先启动游戏。"; return false; }
        Pid = pid;

        handle = Native.OpenProcess(
            Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_OPERATION |
            Native.PROCESS_VM_READ | Native.PROCESS_VM_WRITE, false, Pid);
        if (handle == IntPtr.Zero)
        {
            message = $"无法打开游戏进程（错误码 {Marshal.GetLastWin32Error()}）。请尝试以管理员身份运行本程序。";
            return false;
        }

        if (!LocateAppData(out message))
        {
            Detach();
            return false;
        }
        message = $"已连接 PID {Pid}，已定位存档对象。";
        return true;
    }

    public void Detach()
    {
        if (handle != IntPtr.Zero) { Native.CloseHandle(handle); handle = IntPtr.Zero; }
        Instance = 0; Klass = 0;
    }

    /// <summary>Print which process access rights are available (diagnostics).</summary>
    public static void Diag(int pid)
    {
        foreach (var (name, mask) in new (string, int)[]
        {
            ("QUERY_LIMITED", 0x1000), ("QUERY_INFORMATION", 0x400),
            ("VM_READ", 0x10), ("VM_WRITE", 0x20), ("VM_OPERATION", 0x08), ("ALL", 0x438)
        })
        {
            IntPtr h = Native.OpenProcess(mask, false, pid);
            Console.WriteLine($"OpenProcess(pid={pid}, {name}=0x{mask:X}) -> 0x{h.ToInt64():X} err={Marshal.GetLastWin32Error()}");
            if (h != IntPtr.Zero) Native.CloseHandle(h);
        }
        IntPtr self = Native.OpenProcess(0x438, false, Environment.ProcessId);
        Console.WriteLine($"OpenProcess(self pid={Environment.ProcessId}) -> 0x{self.ToInt64():X} err={Marshal.GetLastWin32Error()}");
        if (self != IntPtr.Zero) Native.CloseHandle(self);
    }

    public void Dispose() => Detach();

    // ---------------------------------------------------------------- locate

    readonly List<(ulong Base, ulong Size)> regions = new();

    void RefreshRegions()
    {
        regions.Clear();
        ulong addr = 0;
        var mbi = new Native.MBI();
        int sz = Marshal.SizeOf<Native.MBI>();
        while (addr < 0x8000_0000)
        {
            if (Native.VirtualQueryEx(handle, P(addr), out mbi, (IntPtr)sz) == IntPtr.Zero) break;
            ulong b = (ulong)mbi.BaseAddress.ToInt64();
            ulong size = (ulong)mbi.RegionSize.ToInt64();
            if (size == 0) break;
            uint prot = mbi.Protect;
            bool readable = mbi.State == Native.MEM_COMMIT && (prot & 0x100) == 0 && (prot & 0x01) == 0;
            if (readable) regions.Add((b, size));
            ulong next = b + size;
            if (next <= addr) break;
            addr = next;
        }
    }

    IEnumerable<ulong> ScanFor(byte[] pattern)
    {
        const int Chunk = 4 << 20;
        var buf = new byte[Chunk];
        foreach (var (b, size) in regions)
        {
            ulong off = 0;
            while (off < size)
            {
                int want = (int)Math.Min((ulong)Chunk, size - off);
                int got = ReadInto(b + off, buf, want);
                if (got >= pattern.Length)
                {
                    int i = 0;
                    while ((i = IndexOf(buf, got, pattern, i)) >= 0)
                    {
                        yield return b + off + (ulong)i;
                        i++;
                    }
                }
                off += (ulong)want;
            }
        }
    }

    int ReadInto(ulong addr, byte[] buf, int count)
    {
        if (count <= 0) return 0;
        Native.ReadProcessMemory(handle, P(addr), buf, (IntPtr)count, out IntPtr got);
        return (int)got;
    }

    static int IndexOf(byte[] hay, int hayLen, byte[] needle, int start)
    {
        int last = hayLen - needle.Length;
        for (int i = start; i <= last; i++)
        {
            if (hay[i] != needle[0]) continue;
            int j = 1;
            while (j < needle.Length && hay[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }

    bool LocateAppData(out string message)
    {
        message = "";
        RefreshRegions();
        if (regions.Count == 0) { message = "无法读取游戏内存区域，请尝试以管理员身份运行。"; return false; }

        var needle = new byte[] { (byte)'A', (byte)'p', (byte)'p', (byte)'D', (byte)'a', (byte)'t', (byte)'a', 0 };
        var strAddrs = ScanFor(needle).ToList();
        if (strAddrs.Count == 0) { message = "内存扫描失败：找不到 AppData 类型名。游戏版本可能已更新。"; return false; }

        var mainBytes = new byte[] { (byte)'m', (byte)'a', (byte)'i', (byte)'n', 0 };
        var probe = new byte[8];

        foreach (var s in strAddrs)
        {
            var pat = BitConverter.GetBytes((uint)s);
            foreach (var hit in ScanFor(pat).ToList())
            {
                if (hit < 8) continue;
                ulong klass = hit - 8;
                var hdr = new byte[0x100];
                if (!ReadBytes(klass, hdr)) continue;
                if (U32At(hdr, Off.Klass_Name) != (uint)s) continue;

                uint ns = U32At(hdr, Off.Klass_Namespace);
                if (ns == 0 || !ReadBytes(ns, probe)) continue;
                bool nsOk = true;
                for (int i = 0; i < mainBytes.Length; i++) if (probe[i] != mainBytes[i]) { nsOk = false; break; }
                if (!nsOk) continue;

                uint sf = U32At(hdr, Off.Klass_StaticFields);
                if (sf == 0) continue;

                var sfBuf = new byte[8];
                if (!ReadBytes(sf, sfBuf)) continue;
                uint inst = U32At(sfBuf, 0);
                if (inst == 0) continue;

                uint backKlass;
                if (!ReadU32(inst, out backKlass)) continue;
                if (backKlass != (uint)klass) continue;     // self check: instance->klass == class

                Klass = klass;
                Instance = inst;
                message = "ok";
                return true;
            }
        }

        message = "找到了 AppData 类型名，但没能定位到存档实例（可能仍停留在标题画面）。请读取一个存档进入商场后再试。";
        return false;
    }

    // ---------------------------------------------------------------- values

    bool Chain(out ulong ints, out ulong lngs, out string why)
    {
        ints = 0; lngs = 0; why = "";
        if (!Attached) { why = "未连接"; return false; }
        if (Instance == 0) { why = "未定位"; return false; }

        var instBuf = new byte[0x2C0];
        if (!ReadBytes(Instance, instBuf)) { why = "读取 AppData 失败"; return false; }

        uint save = U32At(instBuf, Off.AppData_Save);
        if (save == 0) { why = "游戏还没读取存档（停在标题画面）"; return false; }

        var saveBuf = new byte[0x20];
        if (!ReadBytes(save, saveBuf)) { why = "读取存档容器失败"; return false; }
        uint sp = U32At(saveBuf, Off.MySecure_Prop);
        if (sp == 0) { why = "存档容器为空"; return false; }

        var spBuf = new byte[0x20];
        if (!ReadBytes(sp, spBuf)) { why = "读取存档数据失败"; return false; }
        uint i = U32At(spBuf, Off.SecureProp_Ints);
        uint l = U32At(spBuf, Off.SecureProp_Lngs);
        if (i == 0 || l == 0) { why = "存档数组为空"; return false; }

        if (!ReadU32(i + Off.Arr_MaxLength, out uint ilen) || ilen <= (uint)Off.Idx_DPoint) { why = "整数存档数组异常"; return false; }
        if (!ReadU32(l + Off.Arr_MaxLength, out uint llen) || llen <= (uint)Off.Idx_Money) { why = "长整存档数组异常"; return false; }

        ints = i; lngs = l;
        return true;
    }

    bool ReadSecureNumber(ulong obj, out long plain, out long bitmask)
    {
        plain = 0; bitmask = 0;
        var b = new byte[0x20];
        if (!ReadBytes(obj, b)) return false;
        long bits = (long)U64At(b, Off.SecureNum_Bitmask);
        long orig = (long)U64At(b, Off.SecureNum_Original);
        long val = (long)U64At(b, Off.SecureNum_Value);
        long decoded = bits ^ val;
        if (decoded != orig) return false;      // self-heal / tamper marker -> treat as stale
        plain = decoded;
        bitmask = bits;
        return true;
    }

    ulong ElemAddr(ulong arr, int index)
    {
        var b = new byte[4];
        if (!ReadBytes(arr + (ulong)(Off.Arr_Data + 4 * index), b)) return 0;
        return BitConverter.ToUInt32(b, 0);
    }

    public Values ReadValues()
    {
        var v = new Values();
        LastError = "";
        if (!Chain(out ulong ints, out ulong lngs, out string why))
        {
            LastError = why;
            return v;
        }

        ulong moneyObj = ElemAddr(lngs, Off.Idx_Money);
        ulong heartObj = ElemAddr(ints, Off.Idx_Heart);
        ulong dpointObj = ElemAddr(ints, Off.Idx_DPoint);
        if (moneyObj == 0 || heartObj == 0 || dpointObj == 0)
        {
            LastError = "资源对象地址无效";
            return v;
        }

        if (!ReadSecureNumber(moneyObj, out long money, out _)) { LastError = "金钱数据自校验失败"; return v; }
        if (!ReadSecureNumber(heartObj, out long heart, out _)) { LastError = "心币数据自校验失败"; return v; }
        if (!ReadSecureNumber(dpointObj, out long dpoint, out _)) { LastError = "P币数据自校验失败"; return v; }

        v.Money = money;
        v.Heart = (int)heart;
        v.DPoint = (int)dpoint;
        v.Valid = true;
        return v;
    }

    bool WriteSecureNumber(ulong obj, long plain)
    {
        var b = new byte[0x20];
        if (!ReadBytes(obj, b)) return false;
        long bits = (long)U64At(b, Off.SecureNum_Bitmask);
        long val = plain ^ bits;

        var origBytes = BitConverter.GetBytes(plain);
        var valBytes = BitConverter.GetBytes(val);
        // write the obfuscated copy first, then the plain cache, so the game never
        // observes bitmask^value != original (which it counts as tampering).
        if (!WriteBytes(obj + Off.SecureNum_Value, valBytes)) return false;
        if (!WriteBytes(obj + Off.SecureNum_Original, origBytes)) return false;
        return true;
    }

    public bool WriteValues(long money, int heart, int dpoint, out string message)
    {
        message = "";
        if (!Chain(out ulong ints, out ulong lngs, out string why)) { message = why; return false; }

        ulong moneyObj = ElemAddr(lngs, Off.Idx_Money);
        ulong heartObj = ElemAddr(ints, Off.Idx_Heart);
        ulong dpointObj = ElemAddr(ints, Off.Idx_DPoint);
        if (moneyObj == 0 || heartObj == 0 || dpointObj == 0) { message = "找不到资源对象"; return false; }

        bool ok = WriteSecureNumber(moneyObj, money);
        ok &= WriteSecureNumber(heartObj, (int)heart);       // ints are stored sign-extended
        ok &= WriteSecureNumber(dpointObj, (int)dpoint);
        if (!ok) { message = "写入失败，请尝试以管理员身份运行。"; return false; }
        message = "已修改";
        return true;
    }
}
