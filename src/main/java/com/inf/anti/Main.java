package com.inf.anti;

import java.nio.file.Path;

import com.inf.anti.Logger.Level;

public class Main {
    public static void main(String[] args) {
        Logger.init(Path.of("./"), Level.INFO, 10);

        Logger.info("Nothing built can last forever, and every legend, no matter how great, fades with time.");
    }
}
