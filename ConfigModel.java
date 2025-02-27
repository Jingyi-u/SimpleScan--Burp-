public class ConfigModel {
    private volatile boolean bypass403Enabled;
    private volatile boolean fastjsonEnabled;
    private volatile boolean springbootEnabled;

    public boolean isBypass403Enabled() {
        return bypass403Enabled;
    }

    public void setBypass403Enabled(boolean bypass403Enabled) {
        this.bypass403Enabled = bypass403Enabled;
    }

    public boolean isFastjsonEnabled() {
        return fastjsonEnabled;
    }

    public void setFastjsonEnabled(boolean fastjsonEnabled) {
        this.fastjsonEnabled = fastjsonEnabled;
    }
    public boolean isspringbootEnabled() {
        return fastjsonEnabled;
    }
    public void setSpringbootEnabled(boolean springbootEnabled) {
        this.springbootEnabled = springbootEnabled;
    }
}
