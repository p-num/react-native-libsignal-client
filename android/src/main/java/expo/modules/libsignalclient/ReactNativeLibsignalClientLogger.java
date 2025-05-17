package expo.modules.libsignalclient;
import android.os.health.SystemHealthManager;

import org.signal.libsignal.internal.Native;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import expo.modules.core.interfaces.Function;

public class ReactNativeLibsignalClientLogger {
    static private ArrayList<Function<ReactNativeLibsignalClientLogType, String>> callbacks = new ArrayList<>();

    public ReactNativeLibsignalClientLogger() {}

    public static void initiate() {
        // Native.Logger_Initialize(2, ReactNativeLibsignalClientLogger.class);
    }

    // this function only gets called from inside libsignal
    public static void log(int level, String message, String message2) {
        String lvl = ReactNativeLibsignalClientLogger.level(level);
        ReactNativeLibsignalClientLogger.log(lvl, message, message2);
    }

    private static void log(String level, String msg, String... args) {
        String[] f = {"RLSCLOGGER", level, msg};
        String[] both = Stream.concat(Arrays.stream(f), Arrays.stream(args)).toArray(String[]::new);
        System.out.println(Arrays.toString(both));

        String[] m = {msg};
        String[] messages = Stream.concat(Arrays.stream(m), Arrays.stream(args)).toArray(String[]::new);
        ReactNativeLibsignalClientLogType lg = new ReactNativeLibsignalClientLogType(level, messages);
        ReactNativeLibsignalClientLogger.notifyCallbacks(lg);
    }

    public static void info(String msg, String... args) {
        ReactNativeLibsignalClientLogger.log("INFO", msg, args);
    }

    public static void error(String msg, String... args) {
        ReactNativeLibsignalClientLogger.log("ERROR", msg, args);
    }

    public static void warn(String msg, String... args) {
        ReactNativeLibsignalClientLogger.log("WARN", msg, args);
    }

    public static void debug(String msg, String... args) {
        ReactNativeLibsignalClientLogger.log("DEBUG", msg, args);
    }

    public static void addCallback(Function<ReactNativeLibsignalClientLogType, String> f) {
        ReactNativeLibsignalClientLogger.callbacks.add(f);
    }

    private static void notifyCallbacks(ReactNativeLibsignalClientLogType log) {
        for (Function<ReactNativeLibsignalClientLogType, String> f: ReactNativeLibsignalClientLogger.callbacks) {
            f.apply(new ReactNativeLibsignalClientLogType(log.level(), log.messages()));
        }
    }

    private static String level(int level) {
        switch (level) {
            case 2:
                return "VERBOSE";
            case 3:
                return "DEBUG";
            case 4:
                return "INFO";
            case 5:
                return "WARN";
            case 6:
                return "ERROR";
            case 7:
                return "ASSERT";
            default:
                return "UNKNOWN";
        }
    }
}


