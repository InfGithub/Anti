package com.inf.anti.runtime;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    public enum Level {
        DEBUG, INFO, WARN, ERROR, FATAL
    }

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static BufferedWriter writer;
    private static Level currentLevel = Level.INFO;
    private static Path logFile;
    private static int flushInterval;
    private static int lineCount;
    private static boolean initialized;

    private Logger() {
    }

    public static void init(Path outputDir, Level level, int flushIntervalLines) {
        if (initialized) {
            warn("Logger already initialized, ignoring re-init");
            return;
        }
        currentLevel = level;
        flushInterval = flushIntervalLines;
        lineCount = 0;

        try {
            Files.createDirectories(outputDir);
            logFile = outputDir.resolve("latest.log");
            Files.writeString(logFile, "", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8, StandardOpenOption.APPEND);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    if (writer != null) {
                        writer.flush();
                        writer.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }));

            initialized = true;
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize logger", e);
        }
    }

    public static void setLevel(Level level) {
        currentLevel = level;
    }

    private static void log(Level level, String text) {
        if (!initialized) {
            System.out.printf("[%s] [%s]: %s%n", level, Thread.currentThread().getName(), text);
            return;
        }
        if (level.ordinal() < currentLevel.ordinal()) {
            return;
        }

        String time = LocalDateTime.now().format(formatter);
        String logText = String.format("[%s] [%s/%s]: %s%n",
                time, Thread.currentThread().getName(), level, text);

        synchronized (Logger.class) {
            try {
                writer.write(logText);
                lineCount++;
                if (lineCount >= flushInterval) {
                    writer.flush();
                    lineCount = 0;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.print(logText);
        }
    }

    public static void debug(String text) {
        log(Level.DEBUG, text);
    }

    public static void debug(Object obj) {
        debug(String.valueOf(obj));
    }

    public static void info(String text) {
        log(Level.INFO, text);
    }

    public static void info(Object obj) {
        info(String.valueOf(obj));
    }

    public static void warn(String text) {
        log(Level.WARN, text);
    }

    public static void warn(Object obj) {
        warn(String.valueOf(obj));
    }

    public static void error(String text) {
        log(Level.ERROR, text);
    }

    public static void error(Object obj) {
        error(String.valueOf(obj));
    }

    public static void fatal(String text) {
        log(Level.FATAL, text);
    }

    public static void fatal(Object obj) {
        fatal(String.valueOf(obj));
    }
}