package org.mcp.common.protocol;

/**
 * Options for a request.
 *
 * @param progressCallback The progress callback.
 * @param abortSignal      The abort signal.
 * @param timeoutInSeconds The timeout in seconds.
 */
public record RequestOptions(ProgressCallback progressCallback, AbortSignal abortSignal, long timeoutInSeconds) {
}
