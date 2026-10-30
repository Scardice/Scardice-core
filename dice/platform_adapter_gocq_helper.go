package dice

type SignServerConfig struct {
	SignServers          []*SignServer `json:"signServers"          yaml:"signServers"`
	RuleChangeSignServer int           `json:"ruleChangeSignServer" yaml:"ruleChangeSignServer"`
	MaxCheckCount        int           `json:"maxCheckCount"        yaml:"maxCheckCount"`
	SignServerTimeout    int           `json:"signServerTimeout"    yaml:"signServerTimeout"`
	AutoRegister         bool          `json:"autoRegister"         yaml:"autoRegister"`
	AutoRefreshToken     bool          `json:"autoRefreshToken"     yaml:"autoRefreshToken"`
	RefreshInterval      int           `json:"refreshInterval"      yaml:"refreshInterval"`
}

type SignServer struct {
	URL           string `json:"url"           yaml:"url"`
	Key           string `json:"key"           yaml:"key"`
	Authorization string `json:"authorization" yaml:"authorization"`
}
