package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type SubfinderResult struct {
	Host string `json:"host"`
}

type DNSXResult struct {
	Host  string   `json:"host"`
	A     []string `json:"a,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

func extractSubdomains(inputFile string) ([]string, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	unique := make(map[string]bool)
	var subs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var result SubfinderResult
		if err := json.Unmarshal([]byte(scanner.Text()), &result); err == nil {
			if !unique[result.Host] {
				subs = append(subs, result.Host)
				unique[result.Host] = true
			}
		}
	}
	return subs, scanner.Err()
}

func runDNSX(subs []string, outputFile string, verbose bool) error {
	tmpInput := "temp_input.txt"
	f, err := os.Create(tmpInput)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		fmt.Fprintln(f, sub)
	}
	f.Close()
	defer os.Remove(tmpInput)

	args := []string{"-silent", "-json", "-l", tmpInput, "-o", outputFile}
	cmd := exec.Command("dnsx", args...)
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func parseDNSXResults(outputFile string) ([]DNSXResult, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	unique := make(map[string]DNSXResult)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r DNSXResult
		if err := json.Unmarshal([]byte(scanner.Text()), &r); err == nil {
			unique[r.Host] = r
		}
	}
	var results []DNSXResult
	for _, r := range unique {
		results = append(results, r)
	}
	return results, scanner.Err()
}

func writeValidatedResults(results []DNSXResult, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// --------------- CLI Commands ---------------

var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "Subdomain recon tool using Subfinder + DNSX",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run subdomain enumeration and validation",
	Run: func(cmd *cobra.Command, args []string) {
		if domain == "" {
			color.Red("[-] Please provide a domain using --domain")
			os.Exit(1)
		}

		_ = os.Remove(rawFile)
		_ = os.Remove(outputFile)
		os.MkdirAll("output", 0755)

		color.Cyan("[*] Running Subfinder...")
		subfinderCmd := exec.Command("subfinder", "-d", domain, "-silent", "-oJ", "-o", rawFile)
		subfinderCmd.Stderr = os.Stderr
		if verbose {
			subfinderCmd.Stdout = os.Stdout
		}
		if err := subfinderCmd.Run(); err != nil {
			color.Red("[-] Subfinder failed: %v", err)
			os.Exit(1)
		}

		color.Yellow("[*] Extracting subdomains...")
		subs, err := extractSubdomains(rawFile)
		if err != nil {
			color.Red("[-] Failed to extract subdomains: %v", err)
			os.Exit(1)
		}

		color.Cyan("[*] Running DNSX...")
		if err := runDNSX(subs, outputFile, verbose); err != nil {
			color.Red("[-] DNSX failed: %v", err)
			os.Exit(1)
		}

		results, err := parseDNSXResults(outputFile)
		if err != nil {
			color.Red("[-] Failed to parse DNSX output: %v", err)
			os.Exit(1)
		}

		var filtered []DNSXResult
		for _, r := range results {
			if strings.HasSuffix(r.Host, domain) {
				filtered = append(filtered, r)
			}
		}

		if err := writeValidatedResults(filtered, outputFile); err != nil {
			color.Red("[-] Failed to write validated results: %v", err)
			os.Exit(1)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(filtered, "", "  ")
			fmt.Println(string(data))
		} else {
			color.Green("\n[+] Live Hosts:")
			for _, r := range filtered {
				if len(r.A) > 0 {
					color.Green("%s → %s", r.Host, strings.Join(r.A, ", "))
				} else if r.CNAME != "" {
					color.Magenta("%s → CNAME: %s", r.Host, r.CNAME)
				}
			}
			color.Green("\n[✔] Output saved to %s", outputFile)
		}
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate subdomains from a file using DNSX",
	Run: func(cmd *cobra.Command, args []string) {
		if inputFile == "" || domain == "" {
			color.Red("[-] Please provide both --file and --domain")
			os.Exit(1)
		}

		color.Yellow("[*] Validating domains in %s", inputFile)
		subs, err := extractSubdomains(inputFile)
		if err != nil {
			color.Red("[-] Failed to read input: %v", err)
			os.Exit(1)
		}

		if err := runDNSX(subs, outputFile, verbose); err != nil {
			color.Red("[-] DNSX failed: %v", err)
			os.Exit(1)
		}

		results, err := parseDNSXResults(outputFile)
		if err != nil {
			color.Red("[-] Failed to parse DNSX output: %v", err)
			os.Exit(1)
		}

		if err := writeValidatedResults(results, outputFile); err != nil {
			color.Red("[-] Failed to write output: %v", err)
			os.Exit(1)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(data))
		} else {
			color.Green("\n[✔] Validated results written to %s", outputFile)
		}
	},
}

// Flags
var (
	domain, rawFile, outputFile, inputFile string
	jsonOutput, verbose                    bool
)

func init() {
	// Scan flags
	scanCmd.Flags().StringVar(&domain, "domain", "", "Target domain (required)")
	scanCmd.Flags().StringVar(&rawFile, "raw", "/home/arunexploit/Penturion/output/raw.json", "Raw subfinder output file")
	scanCmd.Flags().StringVar(&outputFile, "output", "/home/arunexploit/Penturion/output/validated.json", "Validated DNSX output")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Print output as JSON")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose command output")

	// Validate flags
	validateCmd.Flags().StringVar(&inputFile, "file", "", "Input file (from subfinder or user)")
	validateCmd.Flags().StringVar(&domain, "domain", "", "Target domain for filtering")
	validateCmd.Flags().StringVar(&outputFile, "output", "/home/arunexploit/Penturion/output/validated.json", "Output file")
	validateCmd.Flags().BoolVar(&jsonOutput, "json", false, "Print output as JSON")
	validateCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose command output")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(validateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
