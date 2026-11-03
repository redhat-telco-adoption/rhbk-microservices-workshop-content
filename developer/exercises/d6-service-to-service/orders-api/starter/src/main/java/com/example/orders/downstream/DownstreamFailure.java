package com.example.orders.downstream;

/** Marker used to return a generic downstream status without exposing remote bodies. */
public final class DownstreamFailure extends RuntimeException {
    private final boolean timeout;
    public DownstreamFailure(boolean timeout) { super("downstream request failed"); this.timeout = timeout; }
    public boolean timeout() { return timeout; }
}
