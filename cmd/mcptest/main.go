package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/terateams/ExecMCP/internal/common"
	envconfig "github.com/terateams/ExecMCP/internal/config"
)

type TestConfig struct {
	ServerURL string   `json:"server_url"`
	HostID    string   `json:"host_id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	UseShell  bool     `json:"use_shell"`
	Timeout   int      `json:"timeout"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "list":
		testListTools()
	case "exec":
		testExecCommand()
	case "list-commands":
		testListCommands()
	case "list-hosts":
		testListHosts()
	case "script":
		testExecScript()
	case "test-connection":
		testConnection()
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("MCP Test Client - Test ExecMCP Server")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run cmd/mcptest/main.go <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  list              List available tools")
	fmt.Println("  exec              Execute a command")
	fmt.Println("  list-commands     List available commands and scripts")
	fmt.Println("  list-hosts        List configured SSH hosts")
	fmt.Println("  script            Execute a script")
	fmt.Println("  test-connection   Test SSH connection")
	fmt.Println("  help              Show this help message")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  EXECMCP_MCP_SERVER_URL    Server URL (default: http://localhost:8081/mcp/sse)")
	fmt.Println("  EXECMCP_MCP_HOST_ID       Host ID for testing (default: test-host)")
	fmt.Println("  EXECMCP_MCP_COMMAND       Command to execute (default: whoami)")
	fmt.Println("  EXECMCP_MCP_ARGS          Command arguments (comma-separated)")
	fmt.Println("  EXECMCP_MCP_USE_SHELL     Use shell (true/false, default: false)")
	fmt.Println("  EXECMCP_MCP_TIMEOUT       Timeout in seconds (default: 30)")
	fmt.Println("  EXECMCP_MCP_LIST_TYPE     List type for list-commands: all, commands, scripts (default: all)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run cmd/mcptest/main.go list")
	fmt.Println("  go run cmd/mcptest/main.go list-commands")
	fmt.Println("  go run cmd/mcptest/main.go list-commands commands")
	fmt.Println("  go run cmd/mcptest/main.go list-commands scripts")
	fmt.Println("  go run cmd/mcptest/main.go exec")
	fmt.Println("  EXECMCP_MCP_LIST_TYPE=commands go run cmd/mcptest/main.go list-commands")
	fmt.Println("  EXECMCP_MCP_SERVER_URL=http://localhost:8081/mcp/sse EXECMCP_MCP_HOST_ID=test-host go run cmd/mcptest/main.go exec")
}

func getTestConfig() TestConfig {
	cfg := TestConfig{
		ServerURL: common.GetEnv(envconfig.EnvMCPServerURL, "http://localhost:8081/mcp/sse"),
		HostID:    common.GetEnv(envconfig.EnvMCPHostID, "test-host"),
		Command:   common.GetEnv(envconfig.EnvMCPCommand, "whoami"),
		UseShell:  common.GetEnvBool(envconfig.EnvMCPUseShell, false),
		Timeout:   common.GetEnvInt(envconfig.EnvMCPTimeout, 30),
	}

	argsStr := common.GetEnv(envconfig.EnvMCPArgs, "")
	if argsStr != "" {
		// Simple parsing - in production you'd want something more robust
		cfg.Args = []string{argsStr}
	}

	return cfg
}

func createClient() (*client.Client, error) {
	config := getTestConfig()

	// Create MCP client with SSE transport
	mcpClient, err := client.NewSSEMCPClient(config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP client: %w", err)
	}

	return mcpClient, nil
}

func testListTools() {
	fmt.Println("Testing list tools...")

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	initResponse, err := mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	fmt.Printf("Connected to server: %s v%s\n", initResponse.ServerInfo.Name, initResponse.ServerInfo.Version)

	// List tools
	toolsResponse, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}

	fmt.Printf("\nAvailable tools (%d):\n", len(toolsResponse.Tools))
	for _, tool := range toolsResponse.Tools {
		fmt.Printf("  - %s: %s\n", tool.Name, tool.Description)
		if tool.InputSchema.Properties != nil {
			fmt.Printf("    Schema: %v\n", tool.InputSchema.Properties)
		}
	}
}

func testListCommands() {
	fmt.Println("Testing list commands...")

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	// Get list type from command line argument or environment variable
	listType := "all" // default
	if len(os.Args) > 2 {
		listType = os.Args[2]
	} else if envType := os.Getenv(envconfig.EnvMCPListType); envType != "" {
		listType = envType
	}

	// Validate list type
	validTypes := map[string]bool{"all": true, "commands": true, "scripts": true}
	if !validTypes[listType] {
		log.Fatalf("Invalid list type: %s. Must be one of: all, commands, scripts", listType)
	}

	fmt.Printf("Listing %s...\n", listType)

	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "list_commands",
			Arguments: map[string]interface{}{
				"type": listType,
			},
		},
	}

	result, err := mcpClient.CallTool(ctx, callRequest)
	if err != nil {
		log.Fatalf("Failed to call list_commands: %v", err)
	}

	fmt.Printf("\nAvailable commands and scripts:\n")
	if result.Content != nil {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				// Try to pretty print JSON
				var prettyJSON map[string]interface{}
				if err := json.Unmarshal([]byte(textContent.Text), &prettyJSON); err == nil {
					prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
					fmt.Printf("%s\n", string(prettyBytes))
				} else {
					fmt.Printf("%s\n", textContent.Text)
				}
			} else {
				fmt.Printf("Unknown content type: %T\n", content)
			}
		}
	}

	if result.IsError {
		fmt.Printf("List commands failed\n")
	}
}

func testListHosts() {
	fmt.Println("Testing list hosts...")

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "list_hosts",
			Arguments: map[string]interface{}{},
		},
	}

	result, err := mcpClient.CallTool(ctx, callRequest)
	if err != nil {
		log.Fatalf("Failed to call list_hosts: %v", err)
	}

	fmt.Printf("\nConfigured SSH hosts:\n")
	if result.Content != nil {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				// Try to pretty print JSON
				var prettyJSON map[string]interface{}
				if err := json.Unmarshal([]byte(textContent.Text), &prettyJSON); err == nil {
					prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
					fmt.Printf("%s\n", string(prettyBytes))
				} else {
					fmt.Printf("%s\n", textContent.Text)
				}
			} else {
				fmt.Printf("Unknown content type: %T\n", content)
			}
		}
	}

	if result.IsError {
		fmt.Printf("List hosts failed\n")
	}
}

func testExecCommand() {
	fmt.Println("Testing exec command...")

	config := getTestConfig()

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	// Build arguments
	arguments := map[string]interface{}{
		"host_id":     config.HostID,
		"command":     config.Command,
		"use_shell":   config.UseShell,
		"timeout_sec": config.Timeout,
	}

	if len(config.Args) > 0 {
		var args []interface{}
		for _, arg := range config.Args {
			args = append(args, arg)
		}
		arguments["args"] = args
	}

	fmt.Printf("Executing command on host '%s': %s %v\n", config.HostID, config.Command, config.Args)

	// Call tool
	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "exec_command",
			Arguments: arguments,
		},
	}

	result, err := mcpClient.CallTool(ctx, callRequest)
	if err != nil {
		log.Fatalf("Failed to call tool: %v", err)
	}

	fmt.Printf("\nResult:\n")
	if result.Content != nil {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				fmt.Printf("%s\n", textContent.Text)
			} else {
				fmt.Printf("Unknown content type: %T\n", content)
			}
		}
	}

	if result.IsError {
		fmt.Printf("Error occurred during execution\n")
	}
}

func testExecScript() {
	fmt.Println("Testing exec script...")

	config := getTestConfig()

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	// Call list commands to get available scripts
	listRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "list_commands",
			Arguments: map[string]interface{}{
				"type": "scripts",
			},
		},
	}

	listResult, err := mcpClient.CallTool(ctx, listRequest)
	if err != nil {
		log.Fatalf("Failed to list scripts: %v", err)
	}

	fmt.Printf("Available scripts:\n")
	if listResult.Content != nil {
		for _, content := range listResult.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				fmt.Printf("%s\n", textContent.Text)
			}
		}
	}

	// Get script name from environment variable or use default
	scriptName := common.GetEnv(envconfig.EnvMCPScriptName, "hello-world")
	fmt.Printf("\nAttempting to execute script: %s...\n", scriptName)

	// Parse script parameters from environment variable
	parameters := map[string]interface{}{}
	if paramsStr := common.GetEnv(envconfig.EnvMCPScriptParams, ""); paramsStr != "" {
		if err := json.Unmarshal([]byte(paramsStr), &parameters); err != nil {
			log.Printf("Failed to parse script parameters: %v", err)
		}
	}

	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "exec_script",
			Arguments: map[string]interface{}{
				"host_id":     config.HostID,
				"script_name": scriptName,
				"parameters":  parameters,
				"timeout_sec": config.Timeout,
			},
		},
	}

	result, err := mcpClient.CallTool(ctx, callRequest)
	if err != nil {
		log.Printf("Script execution failed: %v", err)
		return
	}

	fmt.Printf("Result:\n")
	if result.Content != nil {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				fmt.Printf("%s\n", textContent.Text)
			}
		}
	}
}

func testConnection() {
	fmt.Println("Testing connection...")

	config := getTestConfig()

	mcpClient, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the client
	if err := mcpClient.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize client
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities: mcp.ClientCapabilities{
				Roots: &struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{},
			},
			ClientInfo: mcp.Implementation{
				Name:    "ExecMCP-Test-Client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	// Test connection
	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "test_connection",
			Arguments: map[string]interface{}{
				"host_id": config.HostID,
			},
		},
	}

	result, err := mcpClient.CallTool(ctx, callRequest)
	if err != nil {
		log.Fatalf("Failed to test connection: %v", err)
	}

	fmt.Printf("Connection test result:\n")
	if result.Content != nil {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				// Try to pretty print JSON
				var prettyJSON map[string]interface{}
				if err := json.Unmarshal([]byte(textContent.Text), &prettyJSON); err == nil {
					prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
					fmt.Printf("%s\n", string(prettyBytes))
				} else {
					fmt.Printf("%s\n", textContent.Text)
				}
			} else {
				fmt.Printf("Unknown content type: %T\n", content)
			}
		}
	}

	if result.IsError {
		fmt.Printf("Connection test failed\n")
	}
}
