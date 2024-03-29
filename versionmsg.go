package main

// Version is used by the Makefile to set the version
var Version string

// Build is used by the Makefile to set the build, i.e. short git fingerprint
var Build string

var info = "mxcheck --  Copyright (C) 2019-2024  Steffen Fritz -- "

var license = `This program comes with ABSOLUTELY NO WARRANTY.
This is free software under GPL-3.0, and you are welcome to 
redistribute it under certain conditions. See license file.`

var versionmsg = info + " version: " + Version + " build: " + Build + "\n\n" + license + "\n"
