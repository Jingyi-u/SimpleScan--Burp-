public class ConfigModel {
    private volatile boolean bypass403Enabled;
    private volatile boolean fastjsonEnabled;
    private volatile boolean springbootEnabled;
    private volatile boolean corsEnabled;
    private volatile boolean juniorSqlEnabled;
    private volatile boolean findSecretEnabled;

    //bypass 403
    public boolean isBypass403Enabled() {
        return bypass403Enabled;
    }

    public void setBypass403Enabled(boolean bypass403Enabled) {
        this.bypass403Enabled = bypass403Enabled;
    }

    //fastjson
    public boolean isFastjsonEnabled() {
        return fastjsonEnabled;
    }

    public void setFastjsonEnabled(boolean fastjsonEnabled) {
        this.fastjsonEnabled = fastjsonEnabled;
    }

    //springboot
    public boolean isspringbootEnabled() {
        return springbootEnabled;
    }

    public void setSpringbootEnabled(boolean springbootEnabled) {
        this.springbootEnabled = springbootEnabled;
    }

    //cors
    public boolean isCorsEnabled() {
        return corsEnabled;
    }

    public void setCorsEnabled(boolean corsEnabled) {
        this.corsEnabled = corsEnabled;
    }

    //sql
    public boolean isJuniorSqlEnabled(){
        return juniorSqlEnabled;
    }
    public void setJuniorSqlEnabled(boolean juniorSqlEnabled) {
        this.juniorSqlEnabled = juniorSqlEnabled;
    }

    public boolean isFindSecretEnabled() {
        return findSecretEnabled;
    }
    public void setFindSecretEnabled(boolean findSecretEnabled) {
        this.findSecretEnabled = findSecretEnabled;
    }
}
