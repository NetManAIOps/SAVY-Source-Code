package com.netman.yukawa.safeap;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

public class Details extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        System.out.println("Class Details onCreate()");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.details);
        Bundle bundle = this.getIntent().getExtras();
        String fout = bundle.getString("fout");
        TextView myTextView = (TextView) findViewById(R.id.details_display);
        myTextView.setText(fout);
    }
}
