// mxcheck is a security scanner for mail servers
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/logrusorgru/aurora"
)

// verbose controls whether timestamps are prepended to output lines.
var verbose bool

const boxWidth = 52

func printHeader(domain, date string) {
	title := "─ mxcheck "
	fmt.Printf("┌%s%s┐\n", title, strings.Repeat("─", boxWidth-2-len(title)))
	fmt.Printf("│  %-*s│\n", boxWidth-4, "Target: "+domain)
	fmt.Printf("│  %-*s│\n", boxWidth-4, "Date:   "+date)
	fmt.Printf("└%s┘\n", strings.Repeat("─", boxWidth-2))
	fmt.Println()
}

func printSection(name string) {
	if verbose {
		fmt.Printf("\n[%s] %s %s\n", time.Now().Format("15:04:05"), Cyan("▶"), name)
	} else {
		fmt.Printf("\n%s %s\n", Cyan("▶"), name)
	}
}

func printOK(msg string) {
	if verbose {
		fmt.Printf("[%s]   %s %s\n", time.Now().Format("15:04:05"), Green("✓"), msg)
	} else {
		fmt.Printf("  %s %s\n", Green("✓"), msg)
	}
}

func printFail(msg string) {
	if verbose {
		fmt.Printf("[%s]   %s %s\n", time.Now().Format("15:04:05"), Red("✗"), msg)
	} else {
		fmt.Printf("  %s %s\n", Red("✗"), msg)
	}
}

func printWarn(msg string) {
	if verbose {
		fmt.Printf("[%s]   %s %s\n", time.Now().Format("15:04:05"), Yellow("⚠"), msg)
	} else {
		fmt.Printf("  %s %s\n", Yellow("⚠"), msg)
	}
}

func printInfo(key, value string) {
	if verbose {
		fmt.Printf("[%s]   %-24s %s\n", time.Now().Format("15:04:05"), key+":", value)
	} else {
		fmt.Printf("  %-24s %s\n", key+":", value)
	}
}

func printInfoRaw(msg string) {
	if verbose {
		fmt.Printf("[%s]   %s\n", time.Now().Format("15:04:05"), msg)
	} else {
		fmt.Printf("  %s\n", msg)
	}
}

func printError(msg string) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", time.Now().Format("15:04:05"), Red("ERROR:"), msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n", Red("ERROR:"), msg)
	}
}

func printErrorFatal(msg string) {
	printError(msg)
	os.Exit(1)
}
