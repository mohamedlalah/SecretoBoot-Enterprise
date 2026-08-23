using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SecretoBoot.V9.Desktop
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal sealed class SystemView
    {
        internal string Family;
        internal string Distribution;
        internal string Confidence;
        internal string Filesystem;
        internal string DetectionStatus;
    }

    internal sealed class DiscoveryView
    {
        internal string Status = "Not scanned";
        internal int Candidates;
        internal int Systems;
        internal int Evidence;
        internal int Correlations;
        internal readonly List<SystemView> Items = new List<SystemView>();
        internal readonly List<BootEntryView> BootEntries = new List<BootEntryView>();
        internal string ConfigPreviewStatus = "Not generated";
        internal string DiagnosticReport = "Diagnostics unavailable.";
        internal string RefindSetupReport = "rEFInd setup preview unavailable.";
        internal string EndToEndPlanJson = "";
        internal bool Deployable;
        internal readonly List<ManualCandidateView> ManualCandidates = new List<ManualCandidateView>();
        internal bool HasFailure;
        internal string FailureReport = "Safe failure diagnostics unavailable.";
    }

    internal sealed class BootEntryView
    {
        internal string DisplayName;
        internal string Family;
        internal string Confidence;
        internal string IconKind;
        internal string Readiness;
        internal string BootMethod;
    }

    internal sealed class ManualCandidateView
    {
        internal string CandidateId; internal string Family; internal int Disk; internal int Partition; internal string Filesystem; internal long SizeBytes; internal string LoaderPath; internal string DisplayName; internal string PartitionGuid;
        public override string ToString() { return string.Format("{0} — Disk {1}, Partition {2}, {3}, {4:N0} bytes — {5} — GPT {6}", DisplayName, Disk, Partition, Filesystem, SizeBytes, LoaderPath, PartitionGuid); }
    }

    internal sealed class OperationResult
    {
        internal string Status = "FAIL"; internal string Stage = "Unknown"; internal string Reason = "RESULT_MISSING"; internal string Message = "No verified result was returned."; internal string Rollback = "Unknown"; internal string Diagnostic = "Not available";
    }

    internal static class UiText
    {
        internal const string Product = "SecretoBoot V9";
        internal const string Subtitle = "Multi-OS Boot Manager";
        internal const string TestNext = "Test Next Restart";
        internal const string MakeDefault = "Make SecretoBoot Default";
        internal const string RestoreWindows = "Restore Windows as Default";
        internal const string Uninstall = "Uninstall / Rollback";
    }

    internal sealed class MainForm : Form
    {
        // Replaced by the deterministic package builder before compilation.
        private const string ExpectedBridgeSha256 = "__BRIDGE_SHA256__";
        private const string ExpectedDeploymentSha256 = "__DEPLOYMENT_SHA256__";
        private const string ExpectedManualConfirmationSha256 = "__MANUAL_CONFIRMATION_SHA256__";
        private readonly Button scanButton;
        private readonly Button previewButton;
        private readonly Button diagnosticsButton;
        private readonly Button setupButton;
        private readonly Button manageButton;
        private readonly FlowLayoutPanel cards;
        private readonly Label diagnostics;
        private readonly Label bootManagerStatus;
        private readonly Label defaultBootStatus;
        private readonly Label themeDeploymentStatus;
        private DiscoveryView lastView;
        private string firmwareEntryStatus = "Verification required";
        private string stateFreshnessStatus = "Refresh required";

        internal MainForm()
        {
            Text = UiText.Product;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(760, 560);
            Size = new Size(1100, 760);
            BackColor = Color.FromArgb(245, 247, 250);
            Font = new Font("Segoe UI", 10F);

            var header = new Label { Text = UiText.Product, Font = new Font("Segoe UI Semibold", 25F), AutoSize = true, Location = new Point(28, 16) };
            var subtitle = new Label { Text = UiText.Subtitle, Font = new Font("Segoe UI", 12F), ForeColor = Color.FromArgb(80, 89, 104), AutoSize = true, Location = new Point(31, 61) };
            bootManagerStatus = new Label { Text = "Boot Manager: Not installed", Font = new Font("Segoe UI Semibold", 9.5F), ForeColor = Color.FromArgb(65, 74, 89), AutoSize = true, Location = new Point(31, 88) };
            defaultBootStatus = new Label { Text = "Default boot: Windows", Font = new Font("Segoe UI Semibold", 9.5F), ForeColor = Color.FromArgb(65, 74, 89), AutoSize = true, Location = new Point(245, 88) };
            themeDeploymentStatus = new Label { Text = "Theme: FinalRelease.1    Installed revision: NOT INSTALLED    Deployment: NOT INSTALLED", Font = new Font("Segoe UI Semibold", 8.5F), ForeColor = Color.FromArgb(125, 89, 25), AutoSize = true, Location = new Point(31, 110) };
            scanButton = new Button { Text = "Scan Systems", Size = new Size(135, 42), Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(ClientSize.Width - 165, 28), BackColor = Color.FromArgb(31, 111, 235), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += ScanButton_Click;
            previewButton = new Button { Text = "Preview Boot Menu", Size = new Size(165, 42), Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(ClientSize.Width - 340, 28), Enabled = false };
            previewButton.Click += PreviewButton_Click;
            diagnosticsButton = new Button { Text = "Advanced Diagnostics", Size = new Size(175, 42), Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(ClientSize.Width - 525, 28), Enabled = false };
            diagnosticsButton.Click += DiagnosticsButton_Click;
            setupButton = new Button { Text = "rEFInd Setup Preview", Size = new Size(170, 42), Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(ClientSize.Width - 705, 28), Enabled = false };
            setupButton.Click += SetupButton_Click;
            foreach (Button secondary in new[] { previewButton, diagnosticsButton, setupButton }) { secondary.FlatStyle = FlatStyle.Flat; secondary.FlatAppearance.BorderColor = Color.FromArgb(201, 210, 224); secondary.BackColor = Color.White; }
            manageButton = new Button { Text = "Boot Manager Actions", Size = new Size(185, 38), Anchor = AnchorStyles.Bottom | AnchorStyles.Right, Location = new Point(ClientSize.Width - 213, ClientSize.Height - 84), BackColor = Color.FromArgb(19, 49, 91), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            manageButton.FlatAppearance.BorderSize = 0;
            manageButton.Click += ManageButton_Click;
            var aboutButton = new Button { Text = "About", Size = new Size(92, 34), Anchor = AnchorStyles.Bottom | AnchorStyles.Left, Location = new Point(28, ClientSize.Height - 84), BackColor = Color.White, FlatStyle = FlatStyle.Flat };
            aboutButton.FlatAppearance.BorderColor = Color.FromArgb(201, 210, 224);
            aboutButton.Click += delegate { MessageBox.Show(this, "SecretoBoot V9\nMulti-OS Boot Manager\n\nDeveloped by Mohamed LALAH\nSecretoTools\n\nOfficial website:\nsecretotools.com\n\nVersion: 9.0\nBoot manager backend: rEFInd 0.14.2\n\nSecretoBoot uses rEFInd as its boot manager backend. rEFInd attribution and licenses are included with this product.", "About SecretoBoot V9", MessageBoxButtons.OK, MessageBoxIcon.Information); };

            cards = new FlowLayoutPanel { Location = new Point(28, 142), Size = new Size(ClientSize.Width - 56, ClientSize.Height - 240), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right, AutoScroll = true, WrapContents = true, Padding = new Padding(3) };
            diagnostics = new Label { Text = "Discovery Status: Not scanned    Candidates detected: 0    Systems identified: 0    Evidence: 0    Correlations: 0", AutoEllipsis = true, Location = new Point(31, ClientSize.Height - 76), Size = new Size(ClientSize.Width - 62, 38), Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right, ForeColor = Color.FromArgb(65, 74, 89) };

            Controls.Add(header);
            Controls.Add(subtitle);
            Controls.Add(bootManagerStatus);
            Controls.Add(defaultBootStatus);
            Controls.Add(themeDeploymentStatus);
            Controls.Add(scanButton);
            Controls.Add(previewButton);
            Controls.Add(diagnosticsButton);
            Controls.Add(setupButton);
            Controls.Add(manageButton);
            Controls.Add(aboutButton);
            Controls.Add(cards);
            Controls.Add(diagnostics);
            Shown += CheckInterruptedTransaction;
        }

        private void CheckInterruptedTransaction(object sender, EventArgs e)
        {
            RefreshManagementState();
            try { string state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecretoBootV9", "deployment-state.json"); if (!File.Exists(state)) return; string text = File.ReadAllText(state); if (text.IndexOf("\"Stage\": \"DeploymentComplete\"", StringComparison.Ordinal) >= 0 || text.IndexOf("\"Stage\": \"RollbackComplete\"", StringComparison.Ordinal) >= 0 || text.IndexOf("\"Stage\": \"BootNextVerified\"", StringComparison.Ordinal) >= 0 || text.IndexOf("\"Stage\": \"FirmwareEntryRepaired\"", StringComparison.Ordinal) >= 0) return; if (MessageBox.Show(this, "An incomplete SecretoBoot deployment transaction was detected. Start manifest-scoped recovery now?", "Recovery available", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1) == DialogResult.Yes) RunDeployment("Recover", "RECOVER_SECRETOBOOT_TRANSACTION", null); } catch { MessageBox.Show(this, "SecretoBoot could not safely evaluate deployment recovery state.", "Recovery check failed closed", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private async void ScanButton_Click(object sender, EventArgs e)
        {
            var approval = MessageBox.Show(this,
                "Run one bounded read-only SecretoBoot scan, including approved ordinary-volume and directly accessible EFI evidence? No boot, partition, mount, network, or rEFInd changes are permitted.",
                "Read-only scan consent", MessageBoxButtons.YesNo, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2);
            if (approval != DialogResult.Yes) return;

            scanButton.Enabled = false;
            previewButton.Enabled = false;
            diagnosticsButton.Enabled = false;
            setupButton.Enabled = false;
            cards.Controls.Clear();
            diagnostics.Text = "Discovery Status: Scanning    Candidates detected: 0    Systems identified: 0    Evidence: 0    Correlations: 0";
            try
            {
                var view = await Task.Run(() => RunDiscovery());
                lastView = view;
                stateFreshnessStatus = "Current";
                Render(view);
                diagnosticsButton.Tag = view;
                diagnosticsButton.Enabled = true;
                if (view.HasFailure)
                {
                    previewButton.Enabled = false;
                    setupButton.Enabled = false;
                    MessageBox.Show(this, view.FailureReport, "Discovery failed — safe diagnostic", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    previewButton.Tag = view;
                    previewButton.Enabled = true;
                    setupButton.Tag = view;
                    setupButton.Enabled = true;
                }
            }
            catch
            {
                lastView = null; stateFreshnessStatus = "Refresh required";
                diagnostics.Text = "Discovery Status: Failed    Candidates detected: 0    Systems identified: 0    Evidence: 0    Correlations: 0";
                MessageBox.Show(this, "The read-only discovery scan failed. No sensitive path or device details are displayed by this MVP.", "Discovery failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally { scanButton.Enabled = true; }
        }

        private void PreviewButton_Click(object sender, EventArgs e)
        {
            var view = previewButton.Tag as DiscoveryView;
            if (view == null) return;
            cards.SuspendLayout();
            cards.Controls.Clear();
            cards.WrapContents = false;
            var preview = new Panel { Width = Math.Max(700, cards.ClientSize.Width - 28), Height = Math.Max(390, cards.ClientSize.Height - 28), Margin = new Padding(5), BackColor = Color.FromArgb(5, 8, 18), BackgroundImageLayout = ImageLayout.Stretch };
            string background = ThemeAsset("background.png"); if (File.Exists(background)) preview.BackgroundImage = LoadImage(background);
            var title = new Label { Text = UiText.Product, ForeColor = Color.White, BackColor = Color.Transparent, Font = new Font("Segoe UI Semibold", 24F), AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Location = new Point(0, 28), Size = new Size(preview.Width, 46) };
            var subtitle = new Label { Text = "CHOOSE YOUR OPERATING SYSTEM", ForeColor = Color.FromArgb(145, 167, 201), BackColor = Color.Transparent, Font = new Font("Segoe UI", 10F), AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Location = new Point(0, 73), Size = new Size(preview.Width, 26) };
            preview.Controls.Add(title); preview.Controls.Add(subtitle);
            var families = new List<BootEntryView>(); foreach (BootEntryView entry in view.BootEntries) if ((entry.Family == "Windows" || entry.Family == "Android" || entry.Family == "Linux") && entry.Readiness == "Ready" && !families.Exists(x => x.Family == entry.Family && FriendlyName(x) == FriendlyName(entry))) families.Add(entry);
            int cardWidth = 180, gap = 34, total = families.Count * cardWidth + Math.Max(0, families.Count - 1) * gap, start = Math.Max(30, (preview.Width - total) / 2);
            for (int i = 0; i < families.Count; i++) { BootEntryView entry = families[i]; string display = FriendlyName(entry); var card = new Panel { BackColor = Color.FromArgb(i == 0 ? 45 : 18, 54, 88), BorderStyle = BorderStyle.FixedSingle, Location = new Point(start + i * (cardWidth + gap), 135), Size = new Size(cardWidth, 205) }; string iconPath = ThemeAsset("icons/" + (entry.Family == "Windows" ? "windows.png" : entry.Family == "Android" ? "android.png" : "linux.png")); var icon = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent, Location = new Point(20, 13), Size = new Size(140, 140), Image = File.Exists(iconPath) ? LoadImage(iconPath) : null }; var name = new Label { Text = display, ForeColor = Color.White, BackColor = Color.Transparent, Font = new Font("Segoe UI Semibold", 13F), TextAlign = ContentAlignment.MiddleCenter, AutoEllipsis = true, Location = new Point(8, 154), Size = new Size(164, 30) }; var ready = new Label { Text = "Ready", ForeColor = Color.FromArgb(105, 235, 180), BackColor = Color.Transparent, Font = new Font("Segoe UI", 9F), TextAlign = ContentAlignment.MiddleCenter, Location = new Point(8, 181), Size = new Size(164, 20) }; card.Controls.Add(icon); card.Controls.Add(name); card.Controls.Add(ready); preview.Controls.Add(card); }
            var footer = new Label { Text = "Restart      Shutdown\nAutomatic boot in 10 seconds  •  Default: Windows", ForeColor = Color.FromArgb(190, 205, 228), BackColor = Color.Transparent, Font = new Font("Segoe UI", 10F), TextAlign = ContentAlignment.MiddleCenter, Location = new Point(0, preview.Height - 68), Size = new Size(preview.Width, 52), Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right }; preview.Controls.Add(footer); cards.Controls.Add(preview);
            cards.ResumeLayout();
            diagnostics.Text = string.Format("SecretoBoot boot preview: {0} operating systems    Default: Windows    Timeout: 10 seconds", families.Count);
        }

        private void DiagnosticsButton_Click(object sender, EventArgs e)
        {
            var view = diagnosticsButton.Tag as DiscoveryView;
            if (view == null) return;
            using (var dialog = new Form { Text = "Discovery Diagnostics", StartPosition = FormStartPosition.CenterParent, Size = new Size(860, 620), MinimizeBox = false, MaximizeBox = false })
            {
                var text = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Text = view.DiagnosticReport, Location = new Point(12, 12), Size = new Size(820, 510), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
                var copy = new Button { Text = "Copy Diagnostics", Size = new Size(150, 36), Location = new Point(682, 535), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
                copy.Click += delegate { if (!string.IsNullOrEmpty(text.Text)) Clipboard.SetText(text.Text); };
                dialog.Controls.Add(text); dialog.Controls.Add(copy); dialog.ShowDialog(this);
            }
        }

        private void SetupButton_Click(object sender, EventArgs e)
        {
            var view = setupButton.Tag as DiscoveryView;
            if (view == null) return;
            using (var dialog = new Form { Text = "rEFInd Setup Preview — NOT DEPLOYED", StartPosition = FormStartPosition.CenterParent, Size = new Size(900, 740), MinimizeBox = false, MaximizeBox = false })
            {
                var text = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Text = view.RefindSetupReport, Location = new Point(12, 12), Size = new Size(860, 500), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
                var manual = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(12, 530), Size = new Size(650, 30), Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
                foreach (ManualCandidateView candidate in view.ManualCandidates) manual.Items.Add(candidate);
                Button deploy = null;
                var confirm = new Button { Text = "Confirm validated candidate", Enabled = manual.Items.Count > 0, Size = new Size(205, 32), Location = new Point(667, 528), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
                confirm.Click += delegate { var candidate = manual.SelectedItem as ManualCandidateView; if (candidate != null && MessageBox.Show(dialog, candidate.ToString() + "\n\nConfirm this validated loader? No filesystem path can be entered manually.", "Manual confirmation required", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes) { ApplyManualCandidate(view, candidate); deploy.Enabled = view.Deployable && (!IsInstalled() || !IsThemeMatch()); } };
                var copy = new Button { Text = "Copy rEFInd Resolution Diagnostics", Size = new Size(285, 36), Location = new Point(355, 625), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
                copy.Click += delegate { if (!string.IsNullOrEmpty(text.Text)) Clipboard.SetText(text.Text); };
                bool installed = IsInstalled(), themeMatch = IsThemeMatch();
                deploy = new Button { Text = installed ? (themeMatch ? "FinalRelease.1 Installed" : "Upgrade Theme + Test") : "Install SecretoBoot", Enabled = view.Deployable && (!installed || !themeMatch), Size = new Size(220, 36), Location = new Point(652, 625), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
                deploy.Click += delegate { if (IsInstalled()) { if (ConfirmThemeUpgrade(dialog)) RunDeployment("UpgradeAndTestNextBoot", "UPGRADE_FINALPOLISH_AND_TEST_NEXT_BOOT", view.EndToEndPlanJson); } else if (ConfirmInstall(dialog)) { RunDeployment("Install", "INSTALL_SECRETOBOOT_EXPERIMENTAL", view.EndToEndPlanJson); } };
                dialog.Controls.Add(text); dialog.Controls.Add(manual); dialog.Controls.Add(confirm); dialog.Controls.Add(copy); dialog.Controls.Add(deploy); dialog.ShowDialog(this);
            }
        }

        private void ApplyManualCandidate(DiscoveryView view, ManualCandidateView candidate)
        {
            string root = AppDomain.CurrentDomain.BaseDirectory; string helper = Path.Combine(root, "Confirm-SecretoBootManualTarget.ps1"); if (!File.Exists(helper) || !HashMatches(helper, ExpectedManualConfirmationSha256)) throw new InvalidOperationException("Manual confirmation component missing or changed.");
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecretoBootV9"); Directory.CreateDirectory(directory); string plan = Path.Combine(directory, "manual-plan.json"); File.WriteAllText(plan, view.EndToEndPlanJson, new UTF8Encoding(false));
            string pwsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"); if (!File.Exists(pwsh)) pwsh = "pwsh.exe";
            var start = new ProcessStartInfo { FileName = pwsh, Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + QuoteArgument(helper) + " -PlanPath " + QuoteArgument(plan) + " -CandidateId " + QuoteArgument(candidate.CandidateId), UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
            using (var process = Process.Start(start)) { string output = process.StandardOutput.ReadToEnd(); process.StandardError.ReadToEnd(); process.WaitForExit(); if (process.ExitCode != 0) throw new InvalidOperationException("Manual confirmation failed closed."); foreach (string line in output.Replace("\r", "").Split('\n')) { string[] fields = line.Split('\t'); if (fields.Length == 2 && fields[0] == "PLAN") view.EndToEndPlanJson = Encoding.UTF8.GetString(Convert.FromBase64String(fields[1])); else if (fields.Length == 2 && fields[0] == "DEPLOYABLE") view.Deployable = fields[1] == "1"; } }
        }

        private bool ConfirmInstall(IWin32Window owner)
        {
            var first = MessageBox.Show(owner, "Install SecretoBoot boot manager? This writes only EFI\\SecretoBoot and creates one SecretoBoot firmware entry. Secure Boot and BitLocker checks must pass.", "Final deployment confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (first != DialogResult.Yes) return false;
            return MessageBox.Show(owner, "Confirm the SecretoBoot installation plan. Existing Microsoft, Android, and Linux EFI files will not be overwritten.", "Confirm SecretoBoot installation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        private bool ConfirmThemeUpgrade(IWin32Window owner)
        {
            return MessageBox.Show(owner, "Upgrade the existing manifest-owned SecretoBoot runtime to FinalRelease.1 and prepare one test restart?\n\nThe current owned files will be backed up first. Microsoft, Bliss OS, Linux, and foreign EFI loaders will not be modified.", "Confirm owned SecretoBoot release upgrade", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        private void ManageButton_Click(object sender, EventArgs e)
        {
            bool installed = IsInstalled(), themeMatch = IsThemeMatch(), tested = HasSuccessfulTest(), compatibilityEnabled = OwnershipBoolean("WindowsFirstCompatibilityMode");
            string primaryManager = GetCurrentPrimaryBootManager();
            bool isDefault = string.Equals(primaryManager, "SecretoBoot", StringComparison.Ordinal);
            bool discoveryPassed = lastView != null && !lastView.HasFailure;
            bool planAvailable = discoveryPassed && lastView.Deployable && !string.IsNullOrWhiteSpace(lastView.EndToEndPlanJson);
            UpgradeActionDecision upgrade = UpgradeActionPolicy.Evaluate(installed, InstalledThemeRevision(), "FinalRelease.1", ThemeState(), IsUpgradeOwnershipEligible(), discoveryPassed, planAvailable);
            bool makeDefaultReady = installed && themeMatch && tested && !isDefault && planAvailable;
            bool compatibilityReady = installed && themeMatch && tested && planAvailable && !compatibilityEnabled && (OwnershipBoolean("BootOrderChangedByMakeDefault") || !string.IsNullOrEmpty(OwnershipField("PersistentDefaultVerifiedUtc")));
            string dialogPlanJson = planAvailable && lastView != null ? lastView.EndToEndPlanJson : null;

            using (var dialog = new Form { Text = "SecretoBoot Boot Manager", StartPosition = FormStartPosition.CenterParent, Size = new Size(540, 520), MinimizeBox = false, MaximizeBox = false })
            {
                var title = new Label { Text = "Boot Manager Actions", Font = new Font(Font.FontFamily, 13F, FontStyle.Bold), Location = new Point(30, 18), Size = new Size(470, 30), ForeColor = Color.FromArgb(31, 41, 55) };
                dialog.Controls.Add(title);

                string statusText = "Status: " + (installed ? "Installed" : "Not installed") +
                    "    Primary: " + primaryManager +
                    "\nDefault OS inside SecretoBoot: Windows" +
                    "\nCompatibility: " + (compatibilityEnabled ? "Enabled" : compatibilityReady ? "Available if needed" : "Not required / unavailable") +
                    "    One-time test: " + (tested ? "Verified" : "Required");
                var state = new Label { Text = statusText, Location = new Point(30, 55), Size = new Size(470, 70), ForeColor = Color.FromArgb(65, 74, 89) };
                dialog.Controls.Add(state);

                Button test = new Button { Text = UiText.TestNext, Enabled = installed && themeMatch && planAvailable, Size = new Size(460, 44), Location = new Point(30, 145), FlatStyle = FlatStyle.Flat };
                test.Click += delegate { RunManagementAction(dialog, "TestNextBoot", "TEST_SECRETOBOOT_NEXT_BOOT", "Prepare SecretoBoot for the next restart only?\n\nThis does not change the permanent boot order.", true, dialogPlanJson); };
                dialog.Controls.Add(test);

                Button makeDefault = new Button { Text = UiText.MakeDefault, Enabled = makeDefaultReady && !compatibilityEnabled, Size = new Size(460, 44), Location = new Point(30, 205), FlatStyle = FlatStyle.Flat };
                makeDefault.Click += delegate { RunManagementAction(dialog, "MakeDefault", "MAKE_SECRETOBOOT_DEFAULT", "SecretoBoot will appear automatically on every normal startup.\n\nWindows Boot Manager will remain installed and can be restored. Continue?", true, dialogPlanJson); };
                dialog.Controls.Add(makeDefault);

                int nextY = 265;
                if (compatibilityReady)
                {
                    Button compatibility = new Button { Text = "Enable Windows-First Compatibility", Enabled = true, Size = new Size(460, 44), Location = new Point(30, nextY), FlatStyle = FlatStyle.Flat };
                    compatibility.Click += delegate { RunManagementAction(dialog, "EnableWindowsFirstCompatibility", "ENABLE_WINDOWS_FIRST_FIRMWARE_COMPATIBILITY", "Your firmware appears to keep Windows first.\n\nEnable compatibility mode so the verified Windows firmware entry launches SecretoBoot while Microsoft bootmgfw.efi remains untouched?", true, dialogPlanJson); };
                    dialog.Controls.Add(compatibility);
                    nextY += 60;
                }

                Button uninstall = new Button { Text = "Uninstall SecretoBoot", Enabled = installed, Size = new Size(460, 44), Location = new Point(30, nextY), FlatStyle = FlatStyle.Flat };
                uninstall.Click += delegate { RunManagementAction(dialog, "Uninstall", "UNINSTALL_SECRETOBOOT_EXPERIMENTAL", "Remove SecretoBoot and restore native Windows boot first if required?\n\nBliss OS / Android, Linux, and foreign EFI loaders will not be modified.", false, null); };
                dialog.Controls.Add(uninstall);
                nextY += 60;

                Button advanced = new Button { Text = "Advanced / Recovery", Enabled = installed, Size = new Size(460, 38), Location = new Point(30, nextY), FlatStyle = FlatStyle.Flat };
                advanced.Click += delegate { ShowAdvancedRecoveryDialog(dialog, installed, themeMatch, isDefault, compatibilityEnabled, planAvailable, upgrade, dialogPlanJson); };
                dialog.Controls.Add(advanced);

                dialog.ShowDialog(this);
            }
        }

        private void RunManagementAction(Form owner, string action, string consent, string prompt, bool needsPlan, string planJson)
        {
            if (MessageBox.Show(owner, prompt, "Confirm action", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            if (needsPlan && string.IsNullOrWhiteSpace(planJson))
            {
                MessageBox.Show(owner, "Run Scan Systems again before this action.", "Fresh scan required", MessageBoxButtons.OK, MessageBoxIcon.Information);
                owner.Close();
                return;
            }
            owner.Close();
            RunDeployment(action, consent, needsPlan ? planJson : null);
        }

        private void ShowAdvancedRecoveryDialog(Form parent, bool installed, bool themeMatch, bool isDefault, bool compatibilityEnabled, bool planAvailable, UpgradeActionDecision upgrade, string dialogPlanJson)
        {
            using (var advanced = new Form { Text = "Advanced / Recovery", StartPosition = FormStartPosition.CenterParent, Size = new Size(520, 430), MinimizeBox = false, MaximizeBox = false })
            {
                var info = new Label { Text = "Recovery tools\nUse these only when troubleshooting or restoring the original boot flow.", Location = new Point(28, 18), Size = new Size(450, 50), ForeColor = Color.FromArgb(65, 74, 89) };
                advanced.Controls.Add(info);

                Button repair = new Button { Text = "Repair SecretoBoot Boot Entry", Enabled = installed && themeMatch, Size = new Size(440, 40), Location = new Point(28, 85), FlatStyle = FlatStyle.Flat };
                repair.Click += delegate { RunManagementAction(advanced, "RepairFirmwareEntry", "REPAIR_SECRETOBOOT_FIRMWARE_ENTRY", "Repair or recreate the SecretoBoot firmware entry?\n\nWindows, Bliss OS, Linux, and other firmware entries will not be modified.", false, null); };
                advanced.Controls.Add(repair);

                Button restoreNative = new Button { Text = "Restore Native Windows Boot", Enabled = compatibilityEnabled, Size = new Size(440, 40), Location = new Point(28, 140), FlatStyle = FlatStyle.Flat };
                restoreNative.Click += delegate { RunManagementAction(advanced, "RestoreNativeWindowsBoot", "RESTORE_NATIVE_WINDOWS_BOOT", "Restore the native Windows Boot Manager path?\n\nSecretoBoot will remain installed, but normal startup will return directly to Windows.", false, null); };
                advanced.Controls.Add(restoreNative);

                Button restorePrevious = new Button { Text = "Restore Previous Windows Default", Enabled = installed && isDefault && planAvailable, Size = new Size(440, 40), Location = new Point(28, 195), FlatStyle = FlatStyle.Flat };
                restorePrevious.Click += delegate { RunManagementAction(advanced, "RestorePreviousDefault", "RESTORE_PREVIOUS_DEFAULT", "Restore the previously recorded Windows-first boot order?\n\nSecretoBoot will remain installed.", true, dialogPlanJson); };
                advanced.Controls.Add(restorePrevious);

                Button themeUpgradeButton = new Button { Text = "Upgrade / Repair Theme", Enabled = upgrade.Enabled, Size = new Size(440, 40), Location = new Point(28, 250), FlatStyle = FlatStyle.Flat };
                themeUpgradeButton.Click += delegate { RunManagementAction(advanced, "UpgradeAndTestNextBoot", "UPGRADE_FINALPOLISH_AND_TEST_NEXT_BOOT", "Upgrade the verified SecretoBoot runtime/theme and prepare one test restart?", true, dialogPlanJson); };
                advanced.Controls.Add(themeUpgradeButton);

                Button close = new Button { Text = "Close", Size = new Size(120, 34), Location = new Point(348, 315), FlatStyle = FlatStyle.Flat };
                close.Click += delegate { advanced.Close(); };
                advanced.Controls.Add(close);

                advanced.ShowDialog(parent);
            }
        }

        private async void RunDeployment(string action, string consent, string planJson)
        {
            string planFile = null;
            try
            {
                string root = AppDomain.CurrentDomain.BaseDirectory;
                string script = Path.Combine(root, "Invoke-SecretoBootDeployment.ps1");
                if (!File.Exists(script) || !HashMatches(script, ExpectedDeploymentSha256)) throw new FileNotFoundException("Deployment component missing or changed.");
                string planArgument = "";
                if (!string.IsNullOrEmpty(planJson)) { string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecretoBootV9"); Directory.CreateDirectory(directory); planFile = Path.Combine(directory, "approved-plan.json"); File.WriteAllText(planFile, planJson, new UTF8Encoding(false)); planArgument = " -PlanPath " + QuoteArgument(planFile); }
                string resultDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecretoBootV9", "results"); Directory.CreateDirectory(resultDirectory); string resultPath = Path.Combine(resultDirectory, Guid.NewGuid().ToString("N") + ".result");
                string pwsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"); if (!File.Exists(pwsh)) pwsh = "pwsh.exe";
                Process process = Process.Start(new ProcessStartInfo { FileName = pwsh, Arguments = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File " + QuoteArgument(script) + " -Action " + action + " -ConsentPhrase " + consent + planArgument + " -ResultPath " + QuoteArgument(resultPath), UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden });
                if (process == null) throw new InvalidOperationException("Elevated helper did not start."); diagnostics.Text = "SecretoBoot operation in progress: " + action; await Task.Run(() => { if (!process.WaitForExit(300000)) { try { process.Kill(); } catch { } throw new TimeoutException("Elevated operation timed out."); } }); int exitCode = process.ExitCode; OperationResult result = ReadOperationResult(resultPath); try { File.Delete(resultPath); } catch { } if (!string.IsNullOrEmpty(planFile)) { try { File.Delete(planFile); } catch { } planFile = null; }
                InvalidateCachedMachineState();
                if (exitCode != 0 || result.Status != "PASS") { if (result.Reason == "OWNED_FIRMWARE_ENTRY_MISSING") firmwareEntryStatus = "Missing — repair available"; else if (result.Reason == "OWNED_FIRMWARE_ENTRY_AMBIGUOUS") firmwareEntryStatus = "Ambiguous — repair blocked"; MessageBox.Show(this, "SecretoBoot test boot could not be prepared.\n\nStage: " + result.Stage + "\nReason: " + result.Reason + "\nRollback status: " + result.Rollback + "\n\nResolver diagnostics: " + result.Diagnostic + "\n\nNo permanent boot-order change was made. No unverified success was reported.", "SecretoBoot operation failed", MessageBoxButtons.OK, MessageBoxIcon.Warning); diagnostics.Text = "Operation failed: " + result.Reason; RefreshManagementState(); return; }
                diagnostics.Text = "Operation verified: " + result.Reason;
                if (result.Reason == "OWNED_FIRMWARE_REPAIR_VERIFIED") firmwareEntryStatus = "Verified";
                RefreshManagementState();
                if (result.Reason == "TEST_BOOT_READY_VERIFIED" || result.Reason == "FINALRELEASE_THEME_UPGRADED_TEST_BOOT_READY") { DialogResult restart = MessageBox.Show(this, "Installed theme revision: " + InstalledThemeRevision() + "\nExpected theme revision: FinalRelease.1\nTheme deployment: " + ThemeState() + "\n\n" + result.Message + "\n\nRestart now?", "One-time test boot verified", MessageBoxButtons.YesNo, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2); if (restart == DialogResult.Yes) Process.Start(new ProcessStartInfo { FileName = "shutdown.exe", Arguments = "/r /t 0", UseShellExecute = false, CreateNoWindow = true }); }
                else MessageBox.Show(this, result.Message, "SecretoBoot operation verified", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { if (!string.IsNullOrEmpty(planFile)) { try { File.Delete(planFile); } catch { } } InvalidateCachedMachineState(); RefreshManagementState(); MessageBox.Show(this, ex.Message, "SecretoBoot deployment did not start", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private static OperationResult ReadOperationResult(string path)
        {
            if (!File.Exists(path)) throw new InvalidDataException("Elevated helper returned no structured result."); string[] lines = File.ReadAllLines(path); if (lines.Length < 7 || lines[0] != "SBRESULT1") throw new InvalidDataException("Elevated helper result was malformed."); var result = new OperationResult(); foreach (string line in lines) { string[] fields = line.Split('\t'); if (fields.Length != 2) continue; if (fields[0] == "STATUS") result.Status = fields[1]; else if (fields[0] == "STAGE") result.Stage = fields[1]; else if (fields[0] == "REASON") result.Reason = fields[1]; else if (fields[0] == "MESSAGE") result.Message = fields[1]; else if (fields[0] == "ROLLBACK") result.Rollback = fields[1]; else if (fields[0] == "DIAGNOSTIC") result.Diagnostic = fields[1]; } if (result.Status != "PASS" && result.Status != "FAIL") throw new InvalidDataException("Elevated helper status was invalid."); return result;
        }

        private static DiscoveryView RunDiscovery()
        {
            string appRoot = AppDomain.CurrentDomain.BaseDirectory;
            string bridge = Path.Combine(appRoot, "UiDiscoveryBridge.ps1");
            if (!File.Exists(bridge) || !HashMatches(bridge, ExpectedBridgeSha256)) throw new InvalidOperationException();

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string installedPwsh = Path.Combine(programFiles, "PowerShell", "7", "pwsh.exe");
            string pwsh = File.Exists(installedPwsh) ? installedPwsh : "pwsh.exe";
            var start = new ProcessStartInfo
            {
                FileName = pwsh,
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + QuoteArgument(bridge) + " -ApproveReadOnlyDiscovery",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using (var process = Process.Start(start))
            {
                if (process == null) throw new InvalidOperationException();
                string output = process.StandardOutput.ReadToEnd();
                process.StandardError.ReadToEnd();
                if (!process.WaitForExit(120000)) throw new TimeoutException("Discovery process timeout.");
                DiscoveryView view = Parse(output);
                if (process.ExitCode != 0 && !view.HasFailure) throw new InvalidOperationException("Discovery process failed without a safe diagnostic.");
                return view;
            }
        }

        private static DiscoveryView Parse(string output)
        {
            var result = new DiscoveryView();
            string[] lines = output.Replace("\r", "").Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 3 || lines[0] != "SBUI1") throw new InvalidDataException();
            foreach (string line in lines)
            {
                string[] fields = line.Split('\t');
                if (fields[0] == "STATUS" && fields.Length == 2) result.Status = fields[1];
                else if (fields[0] == "SUMMARY" && fields.Length == 5)
                {
                    if (!int.TryParse(fields[1], out result.Candidates) || !int.TryParse(fields[2], out result.Systems) || !int.TryParse(fields[3], out result.Evidence) || !int.TryParse(fields[4], out result.Correlations)) throw new InvalidDataException();
                    if (result.Candidates < 0 || result.Candidates > 4096 || result.Systems < 0 || result.Systems > result.Candidates || result.Evidence < 0 || result.Correlations < 0) throw new InvalidDataException();
                }
                else if (fields[0] == "SYSTEM" && fields.Length == 6)
                {
                    result.Items.Add(new SystemView { Family = fields[1], Distribution = fields[2], Confidence = fields[3], Filesystem = fields[4], DetectionStatus = fields[5] });
                }
                else if (fields[0] == "BOOTSUMMARY" && fields.Length == 4)
                {
                    result.ConfigPreviewStatus = fields[3];
                }
                else if (fields[0] == "BOOTENTRY" && fields.Length == 7)
                {
                    result.BootEntries.Add(new BootEntryView { DisplayName = fields[1], Family = fields[2], Confidence = fields[3], IconKind = fields[4], Readiness = fields[5], BootMethod = fields[6] });
                }
                else if (fields[0] == "DIAGREPORT" && fields.Length == 2)
                {
                    byte[] bytes = Convert.FromBase64String(fields[1]);
                    if (bytes.Length > 262144) throw new InvalidDataException();
                    result.DiagnosticReport = Encoding.UTF8.GetString(bytes);
                }
                else if (fields[0] == "REFINDSETUPREPORT" && fields.Length == 2)
                {
                    byte[] bytes = Convert.FromBase64String(fields[1]);
                    if (bytes.Length > 262144) throw new InvalidDataException();
                    result.RefindSetupReport = Encoding.UTF8.GetString(bytes);
                }
                else if (fields[0] == "ENDTOENDPLAN" && fields.Length == 2)
                {
                    byte[] bytes = Convert.FromBase64String(fields[1]); if (bytes.Length > 1048576) throw new InvalidDataException(); result.EndToEndPlanJson = Encoding.UTF8.GetString(bytes);
                }
                else if (fields[0] == "DEPLOYABLE" && fields.Length == 2) result.Deployable = fields[1] == "1";
                else if (fields[0] == "MANUALCANDIDATE" && fields.Length == 10)
                {
                    int disk, partition; long size; if (!int.TryParse(fields[3], out disk) || !int.TryParse(fields[4], out partition) || !long.TryParse(fields[6], out size)) throw new InvalidDataException(); result.ManualCandidates.Add(new ManualCandidateView { CandidateId = Encoding.UTF8.GetString(Convert.FromBase64String(fields[1])), Family = fields[2], Disk = disk, Partition = partition, Filesystem = fields[5], SizeBytes = size, LoaderPath = Encoding.UTF8.GetString(Convert.FromBase64String(fields[7])), DisplayName = fields[8], PartitionGuid = Encoding.UTF8.GetString(Convert.FromBase64String(fields[9])) });
                }
                else if (fields[0] == "ERRORREPORT" && fields.Length == 2)
                {
                    byte[] bytes = Convert.FromBase64String(fields[1]);
                    if (bytes.Length > 32768) throw new InvalidDataException();
                    result.HasFailure = true;
                    result.FailureReport = Encoding.UTF8.GetString(bytes);
                    result.DiagnosticReport = result.FailureReport;
                }
                else if (fields[0] == "ERROR") throw new InvalidDataException();
            }
            if (result.Items.Count != result.Systems || result.BootEntries.Count != result.Systems) throw new InvalidDataException();
            return result;
        }

        private void Render(DiscoveryView view)
        {
            cards.SuspendLayout();
            cards.Controls.Clear();
            cards.WrapContents = true;

            // Primary dashboard policy:
            // - Drive it from discovered systems, because every consolidated system has a
            //   BootEntry placeholder even when strict canonical boot-target evidence is
            //   unavailable on this scan. Using BootEntry.Readiness here can therefore
            //   hide real installed OSes (the exact regression seen on the Acer test PC).
            // - Hide only Unknown-family candidates from the main dashboard; they remain
            //   available in Advanced Diagnostics.
            // - Do not deduplicate by family: two real Android installations should remain
            //   two cards. Deduplicate only identical family/distribution/filesystem tuples.
            int shown = 0;
            int hidden = 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (SystemView system in view.Items)
            {
                if (!ShouldShowSystemOnPrimaryDashboard(system))
                {
                    hidden++;
                    continue;
                }

                string key = (system.Family ?? "") + "|" + (system.Distribution ?? "") + "|" + (system.Filesystem ?? "");
                if (!seen.Add(key)) continue;

                cards.Controls.Add(CreateCard(system));
                shown++;
            }

            cards.ResumeLayout();
            diagnostics.Text = string.Format("Discovery Status: {0}    Detected OS shown: {1}    Systems detected: {2}    Hidden unknown: {3}    Evidence: {4}", view.Status, shown, view.Systems, hidden, view.Evidence);
        }

        private static bool ShouldShowSystemOnPrimaryDashboard(SystemView system)
        {
            if (system == null) return false;
            return
                string.Equals(system.Family, "Windows", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(system.Family, "Android", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(system.Family, "Linux", StringComparison.OrdinalIgnoreCase);
        }

        private static Control CreateCard(SystemView system)
        {
            var panel = new Panel { Width = 292, Height = 160, Margin = new Padding(9), BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            var icon = new Label { Text = IconFor(system.Family), Font = new Font("Segoe UI Semibold", 20F), ForeColor = Color.FromArgb(31, 111, 235), AutoSize = true, Location = new Point(17, 15) };
            var title = new Label { Text = FriendlySystemName(system), Font = new Font("Segoe UI Semibold", 15F), AutoEllipsis = true, Location = new Point(58, 17), Size = new Size(215, 30) };
            bool ready = system.DetectionStatus.IndexOf("ready", StringComparison.OrdinalIgnoreCase) >= 0 || system.Confidence.IndexOf("confirmed", StringComparison.OrdinalIgnoreCase) >= 0;
            var details = new Label { Text = (ready ? "Ready" : "Needs attention") + "\n" + system.Family + "  •  " + system.Filesystem + "\nConfidence: " + system.Confidence, AutoEllipsis = true, Location = new Point(18, 60), Size = new Size(255, 80), ForeColor = ready ? Color.FromArgb(29, 132, 88) : Color.FromArgb(145, 93, 20) };
            panel.Controls.Add(icon); panel.Controls.Add(title); panel.Controls.Add(details);
            return panel;
        }

        private static Control CreateBootCard(BootEntryView entry)
        {
            var panel = new Panel { Width = 292, Height = 135, Margin = new Padding(7), BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            var icon = new Label { Text = IconFor(entry.IconKind), Font = new Font("Segoe UI Semibold", 20F), ForeColor = Color.FromArgb(31, 111, 235), AutoSize = true, Location = new Point(15, 12) };
            var title = new Label { Text = entry.DisplayName, Font = new Font("Segoe UI Semibold", 15F), AutoEllipsis = true, Location = new Point(58, 15), Size = new Size(215, 30) };
            var details = new Label { Text = "Confidence: " + entry.Confidence + "\nBoot readiness: " + entry.Readiness + "\nBoot method: " + entry.BootMethod, AutoEllipsis = true, Location = new Point(17, 55), Size = new Size(255, 70), ForeColor = entry.Readiness == "Ready" ? Color.FromArgb(34, 139, 94) : Color.FromArgb(160, 103, 20) };
            panel.Controls.Add(icon); panel.Controls.Add(title); panel.Controls.Add(details);
            return panel;
        }

        private static string IconFor(string family)
        {
            if (string.Equals(family, "Windows", StringComparison.OrdinalIgnoreCase)) return "W";
            if (string.Equals(family, "Android", StringComparison.OrdinalIgnoreCase)) return "A";
            if (string.Equals(family, "Linux", StringComparison.OrdinalIgnoreCase)) return "L";
            return "?";
        }

        private static string FriendlyName(BootEntryView entry) { return FriendlyNamePolicy.ForFamily(entry.Family, entry.DisplayName); }
        private static string FriendlySystemName(SystemView system) { return FriendlyNamePolicy.ForFamily(system.Family, system.Distribution); }
        private static string ThemeAsset(string relative) { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "resources", "refind", "0.14.2", "themes", "SecretoBootV9", relative.Replace('/', Path.DirectorySeparatorChar)); }
        private static Image LoadImage(string path) { using (var source = Image.FromFile(path)) return new Bitmap(source); }
        private static string OwnershipPath() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecretoBootV9", "ownership-manifest.json"); }
        private static string TransactionPath() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecretoBootV9", "deployment-state.json"); }
        private static bool IsInstalled() { return File.Exists(OwnershipPath()); }
        private static string OwnershipField(string name) { try { if (!File.Exists(OwnershipPath())) return null; string text = File.ReadAllText(OwnershipPath()); Match match = Regex.Match(text, "\\\"" + Regex.Escape(name) + "\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"", RegexOptions.CultureInvariant); return match.Success ? match.Groups[1].Value : null; } catch { return null; } }
        private static int? JsonIntegerField(string text, string name) { Match match = Regex.Match(text, "\\\"" + Regex.Escape(name) + "\\\"\\s*:\\s*([0-9]+)", RegexOptions.CultureInvariant); int value; return match.Success && int.TryParse(match.Groups[1].Value, out value) ? (int?)value : null; }
        private static string JsonStringField(string text, string name) { Match match = Regex.Match(text, "\\\"" + Regex.Escape(name) + "\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"", RegexOptions.CultureInvariant); return match.Success ? match.Groups[1].Value : null; }
        private static string InstalledThemeRevision() { if (!IsInstalled()) return "NOT INSTALLED"; string theme = OwnershipField("ThemeRevision"); if (!string.IsNullOrEmpty(theme)) return theme; string revision = OwnershipField("Revision"); return string.IsNullOrEmpty(revision) ? "UNKNOWN" : revision.Replace("Windows-Desktop-RealMachine-", "").Replace("Windows-Desktop-V9-", ""); }
        private static bool IsThemeMatch() { return string.Equals(OwnershipField("ThemeRevision"), "FinalRelease.1", StringComparison.Ordinal) && string.Equals(OwnershipField("ThemeDeployment"), "MATCH", StringComparison.Ordinal); }
        private static string ThemeState() { return !IsInstalled() ? "NOT INSTALLED" : IsThemeMatch() ? "MATCH" : "STALE"; }
        private static bool IsUpgradeOwnershipEligible() { try { if (!IsInstalled()) return false; string revision = OwnershipField("Revision"), guid = OwnershipField("TargetEspPartitionGuid"), loadOption = OwnershipField("FirmwareLoadOptionBase64"); Guid parsed; string text = File.ReadAllText(OwnershipPath()); return (revision == "Windows-Desktop-RealMachine-OneShot.2" || revision == "Windows-Desktop-V9-FinalPolish.1" || revision == "Windows-Desktop-V9-FinalPolish.2" || revision == "Windows-Desktop-V9-FinalRelease.1") && Guid.TryParse(guid, out parsed) && parsed != Guid.Empty && !string.IsNullOrEmpty(loadOption) && Regex.IsMatch(text, "\\\"SchemaVersion\\\"\\s*:\\s*\\\"v9-ownership-manifest-1\\\"", RegexOptions.CultureInvariant) && Regex.IsMatch(text, "\\\"OwnershipVerified\\\"\\s*:\\s*true", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) && Regex.IsMatch(text, "\\\"FirmwareEntryNumber\\\"\\s*:\\s*[0-9]+", RegexOptions.CultureInvariant) && text.IndexOf("\"InstalledFiles\"", StringComparison.Ordinal) >= 0; } catch { return false; } }
        private static bool HasSuccessfulTest() { try { if (!File.Exists(TransactionPath()) || !File.Exists(OwnershipPath())) return false; string test = File.ReadAllText(TransactionPath()), ownership = File.ReadAllText(OwnershipPath()); if (test.IndexOf("\"BootNextVerified\": true", StringComparison.OrdinalIgnoreCase) < 0) return false; int? testEntry = JsonIntegerField(test, "TestFirmwareEntryNumber"), ownedEntry = JsonIntegerField(ownership, "FirmwareEntryNumber"); string testGuid = JsonStringField(test, "TestPartitionGuid"), ownedGuid = JsonStringField(ownership, "TargetEspPartitionGuid"), testHash = JsonStringField(test, "TestRefindSha256"), ownedHash = JsonStringField(ownership, "refind_x64.efi"), testRevision = JsonStringField(test, "TestInstalledRevision"), ownedRevision = JsonStringField(ownership, "Revision"), testDigest = JsonStringField(test, "TestInstalledIdentityDigest"); return testEntry.HasValue && ownedEntry.HasValue && testEntry.Value == ownedEntry.Value && string.Equals(testGuid, ownedGuid, StringComparison.OrdinalIgnoreCase) && string.Equals(testHash, ownedHash, StringComparison.Ordinal) && string.Equals(testRevision, ownedRevision, StringComparison.Ordinal) && !string.IsNullOrEmpty(testDigest); } catch { return false; } }
        private static bool OwnershipBoolean(string name) { try { return File.Exists(OwnershipPath()) && Regex.IsMatch(File.ReadAllText(OwnershipPath()), "\\\"" + Regex.Escape(name) + "\\\"\\s*:\\s*true", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); } catch { return false; } }
        internal static string PrimaryBootManagerFromFirmwareText(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return "Verification required";
            string normalized = text.Replace("\r\n", "\n"); string[] blocks = Regex.Split(normalized, "\\n\\s*\\n"); string manager = null;
            foreach (string block in blocks) if (block.IndexOf("{fwbootmgr}", StringComparison.OrdinalIgnoreCase) >= 0) { manager = block; break; }
            if (string.IsNullOrEmpty(manager)) return "Verification required";
            Match order = Regex.Match(manager, "(?im)^\\s*displayorder\\s+(\\{(?:bootmgr|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\\})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!order.Success) return "Verification required"; string first = order.Groups[1].Value;
            if (string.Equals(first, "{bootmgr}", StringComparison.OrdinalIgnoreCase)) { foreach (string block in blocks) if (block.IndexOf("{bootmgr}", StringComparison.OrdinalIgnoreCase) >= 0 && block.IndexOf("\\EFI\\SECRETOBOOT\\REFIND_X64.EFI", StringComparison.OrdinalIgnoreCase) >= 0) return "SecretoBoot (Windows-First Compatibility)"; return "Windows"; }
            foreach (string block in blocks) if (block.IndexOf(first, StringComparison.OrdinalIgnoreCase) >= 0 && block.IndexOf("\\EFI\\SECRETOBOOT\\REFIND_X64.EFI", StringComparison.OrdinalIgnoreCase) >= 0 && block.IndexOf("SecretoBoot", StringComparison.OrdinalIgnoreCase) >= 0) return "SecretoBoot";
            return "Other";
        }
        private static string GetCurrentPrimaryBootManager()
        {
            try
            {
                string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "bcdedit.exe"); if (!File.Exists(executable)) return "Verification required";
                using (var process = Process.Start(new ProcessStartInfo { FileName = executable, Arguments = "/enum firmware", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }))
                {
                    if (process == null) return "Verification required"; string output = process.StandardOutput.ReadToEnd(); process.StandardError.ReadToEnd(); if (!process.WaitForExit(5000) || process.ExitCode != 0 || output.Length > 1048576) return "Verification required"; return PrimaryBootManagerFromFirmwareText(output);
                }
            }
            catch { return "Verification required"; }
        }
        private void InvalidateCachedMachineState() { lastView = null; previewButton.Tag = null; diagnosticsButton.Tag = null; setupButton.Tag = null; previewButton.Enabled = false; diagnosticsButton.Enabled = false; setupButton.Enabled = false; stateFreshnessStatus = "Refresh required"; firmwareEntryStatus = "Verification required"; }
        private void RefreshManagementState() { bool installed = IsInstalled(); string theme=ThemeState(), primaryManager=GetCurrentPrimaryBootManager(); bootManagerStatus.Text = "Boot Manager: " + (installed ? "Installed" : "Not installed"); bootManagerStatus.ForeColor = installed ? Color.FromArgb(29, 132, 88) : Color.FromArgb(125, 89, 25); defaultBootStatus.Text = "Primary boot manager: " + primaryManager; themeDeploymentStatus.Text = "Default OS inside SecretoBoot: Windows    Theme: FinalRelease.1    Installed revision: " + InstalledThemeRevision() + "    Deployment: " + theme; themeDeploymentStatus.ForeColor = theme == "MATCH" ? Color.FromArgb(29, 132, 88) : Color.FromArgb(145, 93, 20); }

        private static bool HashMatches(string path, string expected)
        {
            using (var stream = File.OpenRead(path))
            using (var sha = SHA256.Create())
            {
                var actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                return string.Equals(actual, expected, StringComparison.Ordinal);
            }
        }

        private static string QuoteArgument(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }
    }
}
