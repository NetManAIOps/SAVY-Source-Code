package com.netman.yukawa.safeap;

import android.app.Application;

public class State extends Application {
    private int myState;
    public int getState() {
        return myState;
    }
    public void setState( int i) {
        myState = i;
    }
}
