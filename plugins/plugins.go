package plugins

import (
	"fmt"
	"log"
	"plugin"

	"github.com/fusion/kittendns/config"
)

type Plugins struct {
	PreHandler  []PreHandler
	PostHandler []PostHandler
}

func Load(cfg *config.Config) *Plugins {
	plugins := &Plugins{}

	for _, pluginDef := range cfg.Plugin {
		if !pluginDef.Enabled {
			continue
		}
		plug, err := plugin.Open(pluginDef.Path)
		if err != nil {
			log.Fatal(fmt.Sprintf("Unable to load specified helper plugin: %s", err))
		}
		if pluginDef.PreHandler != "" {
			nph, err := plug.Lookup(pluginDef.PreHandler)
			if err != nil {
				log.Fatal(fmt.Sprintf("Unable to find pre handler ('%s') in loaded helper plugin", pluginDef.PreHandler))
			}
			initFunc, ok := nph.(func() PreHandler)
			if !ok {
				log.Fatal("Loaded helper plugin lacks a proper pre handler function")
			}
			preHandler := initFunc()
			plugins.PreHandler = append(plugins.PreHandler, preHandler)
			fmt.Println("Loaded pre handler:", pluginDef.PreHandler)
		}
		if pluginDef.PostHandler != "" {
			nph, err := plug.Lookup(pluginDef.PostHandler)
			if err != nil {
				log.Fatal(fmt.Sprintf("Unable to find post handler ('%s') in loaded helper plugin", pluginDef.PostHandler))
			}
			initFunc, ok := nph.(func() PostHandler)
			if !ok {
				log.Fatal("Loaded helper plugin lacks a proper post handler function")
			}
			postHandler := initFunc()
			plugins.PostHandler = append(plugins.PostHandler, postHandler)
			fmt.Println("Loaded post handler:", pluginDef.PostHandler)
		}
	}
	return plugins
}
