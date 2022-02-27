package com.izak.thread;

import android.util.Log;

public class MyThread implements Runnable {
    private static final String TAG = "MyThread";
    final MyWork myWork;

    MyThread(MyWork work){
        myWork = work;
    }

    @Override
    public void run() {
        synchronized (myWork) {
            Log.e(TAG, "run: -------------------------------------------------");
            if (myWork.Work()) {
                Log.e(TAG, "run: Processes Success");
            }
            else {
                Log.e(TAG, "run: Processes Failed");
            }
            Log.e(TAG, "run: -------------------------------------------------");
        }

    }
}
