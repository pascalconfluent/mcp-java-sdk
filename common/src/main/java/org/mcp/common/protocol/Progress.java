package org.mcp.common.protocol;

/**
 * Represents a progress value and a total value.
 *
 * @param progress The current progress value.
 * @param total    The total value.
 */
public record Progress(int progress, int total) {
}
