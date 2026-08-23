namespace SecretoBoot.V9.Desktop
{
    public sealed class UpgradeActionDecision
    {
        public bool Visible { get; private set; }
        public bool Enabled { get; private set; }
        public string Reason { get; private set; }
        internal UpgradeActionDecision(bool enabled, string reason) { Visible = true; Enabled = enabled; Reason = reason; }
    }

    public static class UpgradeActionPolicy
    {
        public static UpgradeActionDecision Evaluate(bool installed, string installedThemeRevision, string expectedThemeRevision, string themeDeployment, bool ownershipEligible, bool discoveryPassed, bool validatedPlanAvailable)
        {
            if (!installed) return new UpgradeActionDecision(false, "NOT_INSTALLED");
            if (themeDeployment == "MATCH" && installedThemeRevision == expectedThemeRevision) return new UpgradeActionDecision(false, "THEME_ALREADY_CURRENT");
            if (themeDeployment != "STALE") return new UpgradeActionDecision(false, "THEME_STATE_NOT_STALE");
            if (!ownershipEligible) return new UpgradeActionDecision(false, "OWNERSHIP_UPGRADE_CONTRACT_INVALID");
            if (!discoveryPassed) return new UpgradeActionDecision(false, "DISCOVERY_PASS_REQUIRED");
            if (!validatedPlanAvailable) return new UpgradeActionDecision(false, "VALIDATED_UPGRADE_PLAN_REQUIRED");
            return new UpgradeActionDecision(true, "READY");
        }
    }
}
