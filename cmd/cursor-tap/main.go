package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/burpheart/cursor-tap/internal/ca"
	"github.com/burpheart/cursor-tap/internal/proxy"
	"github.com/burpheart/cursor-tap/pkg/types"
	"github.com/spf13/cobra"
)

var (
	httpPort      int
	socks5Port    int
	apiPort       int
	certDir       string
	dataDir       string
	upstreamProxy string

	// HTTP parsing flags
	enableHTTPParsing bool
	httpLogLevel      int
	httpRecordFile    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cursor-tap",
		Short: "MITM proxy with TLS interception",
		Long:  `A high-performance HTTP/SOCKS5 MITM proxy with TLS decryption and KeyLog export.`,
	}

	// start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy server",
		RunE:  runStart,
	}
	startCmd.Flags().IntVar(&httpPort, "http-port", 8080, "HTTP proxy port")
	startCmd.Flags().IntVar(&socks5Port, "socks5-port", 1080, "SOCKS5 proxy port")
	startCmd.Flags().IntVar(&apiPort, "api-port", 9090, "Management API port")
	startCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")
	startCmd.Flags().StringVar(&dataDir, "data-dir", "", "Data storage directory (default: cert-dir/data)")
	startCmd.Flags().StringVar(&upstreamProxy, "upstream", "", "Upstream proxy URL (e.g., socks5://127.0.0.1:7890)")
	startCmd.Flags().BoolVar(&enableHTTPParsing, "http-parse", false, "Enable HTTP stream parsing and logging")
	startCmd.Flags().IntVar(&httpLogLevel, "http-log", 1, "HTTP log level (0=none, 1=basic, 2=headers, 3=body, 4=debug)")
	startCmd.Flags().StringVar(&httpRecordFile, "http-record", "", "JSONL file for HTTP traffic recording (enables --http-parse)")

	// ca command
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "CA certificate management",
	}

	caInfoCmd := &cobra.Command{
		Use:   "info",
		Short: "Show CA certificate information",
		RunE:  runCAInfo,
	}
	caInfoCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")

	caExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export CA certificate",
		RunE:  runCAExport,
	}
	caExportCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")
	var outputPath string
	caExportCmd.Flags().StringVarP(&outputPath, "output", "o", "./ca.crt", "Output file path")

	caRegenerateCmd := &cobra.Command{
		Use:   "regenerate",
		Short: "Regenerate CA certificate",
		RunE:  runCARegenerate,
	}
	caRegenerateCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")
	var force bool
	caRegenerateCmd.Flags().BoolVar(&force, "force", false, "Force regeneration without confirmation")

	caCleanCertsCmd := &cobra.Command{
		Use:   "clean-certs",
		Short: "Clean cached server certificates",
		RunE:  runCACleanCerts,
	}
	caCleanCertsCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")

	caCmd.AddCommand(caInfoCmd, caExportCmd, caRegenerateCmd, caCleanCertsCmd)

	// sessions command
	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: "List active sessions",
		RunE:  runSessions,
	}
	sessionsCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")

	// stats command
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics",
		RunE:  runStats,
	}
	statsCmd.Flags().StringVar(&certDir, "cert-dir", "~/.cursor-tap", "Certificate storage directory")

	rootCmd.AddCommand(startCmd, caCmd, sessionsCmd, statsCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	// Expand paths
	certDir = expandPath(certDir)
	if dataDir == "" {
		dataDir = filepath.Join(certDir, "data")
	} else {
		dataDir = expandPath(dataDir)
	}

	// If http-record is set, enable http-parse automatically
	if httpRecordFile != "" {
		enableHTTPParsing = true
		httpRecordFile = expandPath(httpRecordFile)
	}

	// Web UI and WebSocket only receive traffic when a Recorder exists (server.go).
	// If the user enabled parsing but did not set a path, persist to the data dir by default.
	if enableHTTPParsing && httpRecordFile == "" {
		httpRecordFile = filepath.Join(dataDir, "http.jsonl")
	}

	// Create config
	config := types.Config{
		HTTPPort:          httpPort,
		SOCKS5Port:        socks5Port,
		APIPort:           apiPort,
		CertDir:           certDir,
		DataDir:           dataDir,
		UpstreamProxy:     upstreamProxy,
		EnableHTTPParsing: enableHTTPParsing,
		HTTPLogLevel:      types.LogLevel(httpLogLevel),
		HTTPRecordFile:    httpRecordFile,
	}

	// Print startup info
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║           cursor-tap Proxy Starting           ║")
	fmt.Println("╠══════════════════════════════════════════╣")
	fmt.Printf("║  HTTP Proxy:    127.0.0.1:%-15d║\n", config.HTTPPort)
	fmt.Printf("║  SOCKS5 Proxy:  127.0.0.1:%-15d║\n", config.SOCKS5Port)
	fmt.Printf("║  API Server:    127.0.0.1:%-15d║\n", config.APIPort)
	fmt.Printf("║  Cert Dir:      %-25s║\n", truncateString(config.CertDir, 25))
	fmt.Printf("║  Data Dir:      %-25s║\n", truncateString(config.DataDir, 25))
	if config.UpstreamProxy != "" {
		fmt.Printf("║  Upstream:      %-25s║\n", truncateString(config.UpstreamProxy, 25))
	}
	if config.EnableHTTPParsing {
		fmt.Printf("║  HTTP Parse:    %-25s║\n", fmt.Sprintf("enabled (level %d)", config.HTTPLogLevel))
	}
	if config.HTTPRecordFile != "" {
		fmt.Printf("║  HTTP Record:   %-25s║\n", truncateString(config.HTTPRecordFile, 25))
	}
	fmt.Println("║                                          ║")
	fmt.Println("║  KeyLog: <data-dir>/sslkeys.log          ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println()

	// Create and start server
	server, err := proxy.NewServer(config)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		server.Stop()
	}()

	return server.Start()
}

func runCAInfo(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)

	caInstance, err := ca.New(ca.Options{
		CertDir: certDir,
	})
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	fmt.Printf("CA Certificate: %s\n", caInstance.CertPath())
	fmt.Printf("CA Private Key: %s\n", caInstance.KeyPath())
	fmt.Printf("Cached Certs:   %s (%d certificates)\n", caInstance.CertsDir(), caInstance.CertCount())

	return nil
}

func runCAExport(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)
	outputPath, _ := cmd.Flags().GetString("output")

	caInstance, err := ca.New(ca.Options{
		CertDir: certDir,
	})
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	// Copy CA certificate to output path
	srcPath := caInstance.CertPath()
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open CA cert: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy CA cert: %w", err)
	}

	fmt.Printf("CA certificate exported to: %s\n", outputPath)
	return nil
}

func runCARegenerate(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		fmt.Print("This will regenerate the CA certificate and clear all cached certificates. Continue? [y/N] ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	caInstance, err := ca.New(ca.Options{
		CertDir: certDir,
	})
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	if err := caInstance.Regenerate(); err != nil {
		return fmt.Errorf("regenerate CA: %w", err)
	}

	fmt.Println("CA certificate regenerated successfully.")
	fmt.Printf("New CA certificate: %s\n", caInstance.CertPath())
	return nil
}

func runCACleanCerts(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)

	caInstance, err := ca.New(ca.Options{
		CertDir: certDir,
	})
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	count := caInstance.CertCount()
	if err := caInstance.CleanCerts(); err != nil {
		return fmt.Errorf("clean certs: %w", err)
	}

	fmt.Printf("Cleaned %d cached certificates.\n", count)
	return nil
}

func runSessions(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)
	apiAddr, err := readAPIAddr(certDir)
	if err != nil {
		return fmt.Errorf("proxy not running or API address not found: %w", err)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/api/sessions", apiAddr))
	if err != nil {
		return fmt.Errorf("connect to API: %w", err)
	}
	defer resp.Body.Close()

	var sessions []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions.")
		return nil
	}

	fmt.Printf("%-36s %-30s %-10s %-15s\n", "ID", "Target", "Status", "Bytes")
	fmt.Println(repeatString("-", 95))
	for _, s := range sessions {
		id := s["id"].(string)
		target := fmt.Sprintf("%s:%v", s["target_host"], s["target_port"])
		status := s["status"].(string)
		bytes := fmt.Sprintf("↑%v ↓%v", s["bytes_sent"], s["bytes_received"])
		fmt.Printf("%-36s %-30s %-10s %-15s\n", id, target, status, bytes)
	}

	return nil
}

func runStats(cmd *cobra.Command, args []string) error {
	certDir = expandPath(certDir)
	apiAddr, err := readAPIAddr(certDir)
	if err != nil {
		return fmt.Errorf("proxy not running or API address not found: %w", err)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/api/stats", apiAddr))
	if err != nil {
		return fmt.Errorf("connect to API: %w", err)
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Println("Statistics:")
	fmt.Printf("  Active Sessions:    %v\n", stats["active_sessions"])
	fmt.Printf("  Total Sessions:     %v\n", stats["total_sessions"])
	fmt.Printf("  Total Bytes Sent:   %v\n", stats["total_bytes_sent"])
	fmt.Printf("  Total Bytes Recv:   %v\n", stats["total_bytes_received"])

	return nil
}

// Helper functions

func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

func readAPIAddr(certDir string) (string, error) {
	addrFile := filepath.Join(certDir, "api.addr")
	data, err := os.ReadFile(addrFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
