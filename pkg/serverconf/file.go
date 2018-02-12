package serverconf

import (
	"strconv"
)

type cfg interface {
	// GlobalMap returns a copy of the top-level (global) configuration map.
	GlobalMap() map[string]string
}

type ConfigFile struct {
	cfg
}

func NewConfigFile(path string) (*ConfigFile, error) {
	var f cfg
	f, err := newinicfg(path)
	if err != nil {
		return nil, err
	}
	return &ConfigFile{f}, nil
}

// GlobalConfig returns a new *serverconf.Config representing the top-level
// (global) configuration.
func (c *ConfigFile) GlobalConfig() *Config {
	return New(nil, c.GlobalMap())
}

// ServerConfig returns a new *serverconf.Config with the fallback representing
// the global configuration with server-specific values incremented by id.
// Optionally a persistent map which has priority may be passed. This map
// is consumed and cannot be reused.
func (c *ConfigFile) ServerConfig(id int64, persistentMap map[string]string) *Config {
	m := c.GlobalMap()

	// Some server specific values from the global config must be offset.
	// These are read differently by the server as well.
	if v, ok := m["Port"]; ok {
		i, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			m["Port"] = strconv.FormatInt(i+id-1, 10)
		}
	}
	if v, ok := m["WebPort"]; ok {
		i, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			m["WebPort"] = strconv.FormatInt(i+id-1, 10)
		}
	}

	return New(persistentMap, m)
}
