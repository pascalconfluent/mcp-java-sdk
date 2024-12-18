package org.mcp.common.protocol;

/**
 * A signal that can be used to abort an operation.
 */
public interface AbortSignal {
    /**
     * Returns true if the signal has been aborted.
     *
     * @return True if the signal has been aborted.
     */
    boolean aborted();
}
