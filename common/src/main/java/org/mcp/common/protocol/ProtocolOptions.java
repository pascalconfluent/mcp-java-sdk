package org.mcp.common.protocol;

/**
 * Protocol options for the MCP protocol.
 *
 * @param enforceStrictCapabilities If true, restrict emitted requests to only those that the remote side has indicated that they can handle, through their advertised capabilities.
 */
public record ProtocolOptions(boolean enforceStrictCapabilities) {
}
