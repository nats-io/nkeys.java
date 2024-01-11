package nats.io;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

@SuppressWarnings("DataFlowIssue")
public abstract class ResourceUtils {
    public static List<String> resourceAsLines(String fileName) {
        try {
            ClassLoader classLoader = ResourceUtils.class.getClassLoader();
            File file = new File(classLoader.getResource(fileName).getFile());
            return Files.readAllLines(file.toPath());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] resourceAsBytes(String fileName) {
        try {
            ClassLoader classLoader = ResourceUtils.class.getClassLoader();
            File file = new File(classLoader.getResource(fileName).getFile());
            return Files.readAllBytes(file.toPath());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
