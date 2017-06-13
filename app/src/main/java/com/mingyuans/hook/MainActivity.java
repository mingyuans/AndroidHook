package com.mingyuans.hook;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
        System.loadLibrary("elfhook");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        doElfHookByLinkView();
        doElfHookByExecutableView();

        hookWebViewDns();

        WebView webView = (WebView) findViewById(R.id.wv_main);
        webView.getSettings().setAppCacheEnabled(false);
        webView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);
        webView.getSettings().setJavaScriptEnabled(true);

        webView.loadUrl("https://www.baidu.com");

    }

    private native int doElfHookByLinkView();

    private native int doElfHookByExecutableView();

    private native int hookWebViewDns();

}
