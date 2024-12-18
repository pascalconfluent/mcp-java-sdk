package org.mcp.common.protocol;

/**
 * Callback for progress notifications.
 */
public interface ProgressCallback {
    /**
     * Called when progress is made.
     *
     * @param progress The progress value.
     */
    void onProgress(Progress progress);
}
