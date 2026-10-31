using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace MM2Trainer;

internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0) return Cli.Run(args);

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrainerForm());
        return 0;
    }
}

/// <summary>Hidden command line mode, handy for testing / scripting.</summary>
internal static class Cli
{
    static readonly List<string> lines = new();

    static void W(string s)
    {
        lines.Add(s);
        try { Console.WriteLine(s); } catch { }
    }

    static int Flush(int code)
    {
        try { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory, "cli.log"), lines); } catch { }
        return code;
    }

    public static int Run(string[] argsIn)
    {
        int pidOverride = 0;
        var args = new List<string>();
        for (int i = 0; i < argsIn.Length; i++)
        {
            if (argsIn[i] == "--pid" && i + 1 < argsIn.Length) pidOverride = int.Parse(argsIn[++i]);
            else args.Add(argsIn[i]);
        }
        if (args.Count == 0) return Flush(5);

        if (args[0] == "--diag")
        {
            W("FoundGamePid = " + GameSession.FindGamePid() + "  (override " + pidOverride + ")");
            W("total via .NET = " + Process.GetProcesses().Length + ", byName = " + Process.GetProcessesByName("KairoGames").Length);
            W("Is64BitProcess = " + Environment.Is64BitProcess);
            GameSession.Diag(pidOverride != 0 ? pidOverride : GameSession.FindGamePid());
            return Flush(0);
        }

        using var s = new GameSession();
        if (!s.Attach(out string msg, pidOverride))
        {
            W("ATTACH_FAIL: " + msg);
            return Flush(1);
        }
        W("ATTACH_OK: " + msg + " instance=0x" + s.Instance.ToString("X8"));

        if (args[0] == "--read")
        {
            for (int i = 0; i < 6; i++)
            {
                var v = s.ReadValues();
                if (v.Valid)
                {
                    W("VALUES money=" + v.Money + " heart=" + v.Heart + " dpoint=" + v.DPoint);
                    return Flush(0);
                }
                Thread.Sleep(400);
            }
            W("READ_FAIL: " + s.LastError);
            return Flush(2);
        }

        if (args[0] == "--set" && args.Count >= 4)
        {
            long money = long.Parse(args[1]);
            int heart = int.Parse(args[2]);
            int dpoint = int.Parse(args[3]);
            for (int i = 0; i < 6; i++)
            {
                if (s.ReadValues().Valid) break;
                Thread.Sleep(400);
            }
            if (!s.WriteValues(money, heart, dpoint, out string wmsg))
            {
                W("WRITE_FAIL: " + wmsg);
                return Flush(3);
            }
            Thread.Sleep(300);
            var v = s.ReadValues();
            W("WROTE money=" + v.Money + " heart=" + v.Heart + " dpoint=" + v.DPoint + " valid=" + v.Valid);
            return Flush(v.Valid && v.Money == money && v.Heart == heart && v.DPoint == dpoint ? 0 : 4);
        }

        W("usage: [--pid N] --read | --set <money> <heart> <dpoint>");
        return Flush(5);
    }
}

internal sealed class TrainerForm : Form
{
    static readonly string[] RowNames = { "金钱 (G)", "心币", "P币" };
    static readonly string[] RowPresetText = { "9,999,999", "999", "9,999" };
    static readonly long[] RowMaxValue = { 999_999_999, 9_999, 999_999 };
    static readonly Color Accent = Color.FromArgb(0, 120, 212);

    readonly GameSession session = new();
    readonly System.Windows.Forms.Timer timer = new() { Interval = 500 };
    readonly Label[] lblCur = new Label[3];
    readonly TextBox[] tbInput = new TextBox[3];

    Label lblStatus;
    Label lblSubStatus;
    CheckBox chkAuto;
    TextBox txtLog;
    Button btnRelink;
    bool busy;
    int attachCooldown;
    string lastInvalidReason;

    public TrainerForm()
    {
        BuildUi();
        timer.Tick += OnTick;
        timer.Start();
        Shown += (_, _) => DoAttach();
        FormClosing += (_, _) => { timer.Stop(); session.Dispose(); };
    }

    void BuildUi()
    {
        SuspendLayout();
        Text = "百货商场物语2  修改器  ·  Mega Mall Story 2";
        Font = new Font("Microsoft YaHei UI", 9.75f);
        ClientSize = new Size(468, 456);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        AutoScaleMode = AutoScaleMode.None;
        BackColor = Color.FromArgb(248, 249, 251);

        Controls.Add(new Panel { Location = new Point(0, 0), Size = new Size(468, 8), BackColor = Accent });

        lblStatus = new Label
        {
            Location = new Point(14, 16),
            Size = new Size(330, 22),
            Text = "正在查找游戏进程…",
            Font = new Font(Font.FontFamily, 10f, FontStyle.Bold),
            ForeColor = Color.FromArgb(40, 40, 40)
        };
        Controls.Add(lblStatus);

        lblSubStatus = new Label
        {
            Location = new Point(14, 38),
            Size = new Size(330, 20),
            Text = "",
            ForeColor = Color.FromArgb(120, 120, 120)
        };
        Controls.Add(lblSubStatus);

        btnRelink = new Button
        {
            Location = new Point(354, 18),
            Size = new Size(100, 30),
            Text = "重新定位",
            FlatStyle = FlatStyle.System
        };
        btnRelink.Click += (_, _) => DoAttach();
        Controls.Add(btnRelink);

        var box = new GroupBox
        {
            Text = "  资源  ",
            Location = new Point(12, 66),
            Size = new Size(444, 186),
            ForeColor = Color.FromArgb(90, 90, 90)
        };
        Controls.Add(box);

        for (int i = 0; i < 3; i++)
        {
            int y = 26 + i * 52;

            box.Controls.Add(new Label
            {
                Location = new Point(14, y + 6),
                Size = new Size(76, 22),
                Text = RowNames[i],
                ForeColor = Color.FromArgb(60, 60, 60)
            });

            var cur = new Label
            {
                Location = new Point(92, y),
                Size = new Size(112, 30),
                Text = "-",
                Font = new Font("Consolas", 15f, FontStyle.Bold),
                ForeColor = Accent,
                TextAlign = ContentAlignment.MiddleRight
            };
            lblCur[i] = cur;
            box.Controls.Add(cur);

            var tb = new TextBox
            {
                Location = new Point(214, y + 4),
                Size = new Size(90, 25),
                Text = RowPresetText[i],
                TextAlign = HorizontalAlignment.Right
            };
            tbInput[i] = tb;
            box.Controls.Add(tb);

            int idx = i;
            var set = new Button
            {
                Location = new Point(310, y + 2),
                Size = new Size(56, 28),
                Text = "设为",
                FlatStyle = FlatStyle.System
            };
            set.Click += (_, _) => Apply(idx, null);
            box.Controls.Add(set);

            var max = new Button
            {
                Location = new Point(370, y + 2),
                Size = new Size(58, 28),
                Text = "拉满",
                FlatStyle = FlatStyle.System
            };
            max.Click += (_, _) => Apply(idx, RowMaxValue[idx]);
            box.Controls.Add(max);
        }

        chkAuto = new CheckBox
        {
            Location = new Point(14, 264),
            Size = new Size(160, 22),
            Text = "自动刷新（0.5 秒）",
            Checked = true,
            ForeColor = Color.FromArgb(70, 70, 70)
        };
        Controls.Add(chkAuto);

        Controls.Add(new Label
        {
            Location = new Point(180, 266),
            Size = new Size(276, 20),
            Text = "提示：先进游戏读取存档，再按「设为」",
            ForeColor = Color.FromArgb(140, 140, 140),
            TextAlign = ContentAlignment.MiddleRight
        });

        txtLog = new TextBox
        {
            Location = new Point(14, 292),
            Size = new Size(440, 150),
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.White,
            Font = new Font("Microsoft YaHei UI", 9f),
            BorderStyle = BorderStyle.FixedSingle
        };
        Controls.Add(txtLog);

        ResumeLayout();
        Log("修改器已启动。请让游戏运行在商场画面（已读取存档）。");
    }

    void Log(string msg)
    {
        txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + Environment.NewLine);
    }

    void SetStatus(string main, string sub = "", Color? color = null)
    {
        lblStatus.Text = main;
        lblStatus.ForeColor = color ?? Color.FromArgb(40, 40, 40);
        lblSubStatus.Text = sub;
    }

    void DoAttach()
    {
        if (busy) return;
        busy = true;
        btnRelink.Enabled = false;
        SetStatus("正在定位游戏数据…", "首次定位需要扫描内存，约 1~3 秒", Color.FromArgb(150, 110, 0));

        Task.Run(() =>
        {
            bool ok = session.Attach(out string msg);
            BeginInvoke(() =>
            {
                busy = false;
                btnRelink.Enabled = true;
                if (ok)
                {
                    Log(msg);
                    SetStatus("已连接游戏", "PID " + session.Pid + " · 存档对象 0x" + session.Instance.ToString("X8"),
                        Color.FromArgb(0, 130, 60));
                    RefreshValues(verbose: true);
                }
                else
                {
                    Log("连接失败：" + msg);
                    SetStatus("未连接", msg, Color.FromArgb(190, 60, 60));
                }
            });
        });
    }

    void OnTick(object sender, EventArgs e)
    {
        if (busy) return;

        if (!session.Attached)
        {
            if (attachCooldown-- <= 0)
            {
                attachCooldown = 4;
                DoAttach();
            }
            return;
        }

        if (!IsAlive(session.Pid))
        {
            session.Detach();
            SetStatus("游戏已关闭", "等待游戏重新启动…", Color.FromArgb(150, 150, 150));
            for (int i = 0; i < 3; i++) lblCur[i].Text = "-";
            return;
        }

        if (chkAuto.Checked) RefreshValues(verbose: false);
    }

    static bool IsAlive(int pid)
    {
        try
        {
            var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch { return false; }
    }

    void RefreshValues(bool verbose)
    {
        var v = session.ReadValues();
        if (!v.Valid)
        {
            string why = session.LastError;
            if (!string.IsNullOrEmpty(why) && why != lastInvalidReason)
            {
                lastInvalidReason = why;
                Log(why);
            }
            SetStatus("已连接，但没有可修改的数据", why, Color.FromArgb(150, 110, 0));
            for (int i = 0; i < 3; i++) lblCur[i].Text = "-";
            return;
        }

        lastInvalidReason = null;
        lblCur[0].Text = v.Money.ToString("N0");
        lblCur[1].Text = v.Heart.ToString("N0");
        lblCur[2].Text = v.DPoint.ToString("N0");
        SetStatus("已连接游戏", "PID " + session.Pid + " · 存档对象 0x" + session.Instance.ToString("X8"),
            Color.FromArgb(0, 130, 60));
        if (verbose) Log("读取成功：金钱 " + v.Money.ToString("N0") + " / 心币 " + v.Heart.ToString("N0") + " / P币 " + v.DPoint.ToString("N0"));
    }

    void Apply(int index, long? forced)
    {
        if (!session.Attached) { Log("还没连接游戏，无法修改。"); return; }

        var cur = session.ReadValues();
        if (!cur.Valid) { Log("现在没有可修改的数据：" + session.LastError); return; }

        long target;
        if (forced.HasValue) target = forced.Value;
        else
        {
            string raw = new string((tbInput[index].Text ?? "").Where(char.IsDigit).ToArray());
            if (!long.TryParse(raw, out target) || target < 0)
            {
                Log("「" + RowNames[index] + "」的输入无效：" + tbInput[index].Text);
                return;
            }
        }

        target = Math.Clamp(target, 0, index == 0 ? 999_999_999_999 : 999_999_999);
        long m = index == 0 ? target : cur.Money;
        int h = index == 1 ? (int)target : cur.Heart;
        int d = index == 2 ? (int)target : cur.DPoint;

        if (!session.WriteValues(m, h, d, out string msg))
        {
            Log("修改失败：" + msg);
            return;
        }

        tbInput[index].Text = target.ToString("N0");
        Log("已修改 " + RowNames[index] + " → " + target.ToString("N0"));
        RefreshValues(verbose: false);
    }
}
