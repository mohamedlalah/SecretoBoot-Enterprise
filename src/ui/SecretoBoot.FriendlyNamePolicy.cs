using System;

namespace SecretoBoot.V9.Desktop
{
    public static class FriendlyNamePolicy
    {
        public static string ForFamily(string family, string evidenceName)
        {
            string name = (evidenceName ?? "").Trim();
            if (string.Equals(family, "Android", StringComparison.OrdinalIgnoreCase))
            {
                if (name.IndexOf("Bliss", StringComparison.OrdinalIgnoreCase) >= 0) return "Bliss OS";
                if (name.IndexOf("Android-x86", StringComparison.OrdinalIgnoreCase) >= 0) return "Android-x86";
                return "Android";
            }
            if (string.Equals(family, "Windows", StringComparison.OrdinalIgnoreCase))
            {
                if (name.IndexOf("Windows 11", StringComparison.OrdinalIgnoreCase) >= 0) return "Windows 11";
                if (name.IndexOf("Windows 10", StringComparison.OrdinalIgnoreCase) >= 0) return "Windows 10";
                return "Windows";
            }
            if (string.Equals(family, "Linux", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string known in new[] { "Ubuntu", "Zorin OS", "Fedora", "Debian" })
                    if (string.Equals(name, known, StringComparison.OrdinalIgnoreCase)) return known;
                return "Linux";
            }
            return "Unknown system";
        }
    }
}
