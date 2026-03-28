package main

import (
	"encoding/json"
	"net/http"
)

type MXCVersion struct {
	Tag_name string
}

func getLatestVersion() error {
	url := "https://api.github.com/repos/steffenfritz/mxcheck/releases/latest"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var mxcv MXCVersion
	jsondec := json.NewDecoder(resp.Body)
	if err = jsondec.Decode(&mxcv); err != nil {
		return err
	}

	if mxcv.Tag_name == Version {
		InfoLogger.Println("You have the most recent version installed. Version: " + Version)
	} else {
		InfoLogger.Println("A newer version is available.")
		InfoLogger.Println("Installed version: " + Version)
		InfoLogger.Println("Available version: " + mxcv.Tag_name)
	}

	return nil
}
