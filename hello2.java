import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class MainScanner {

    private static List<Path> files;  // Stores JS and JSX files
    private static List<JCheckBox> checkBoxes; // Stores checkboxes

    public static void scanProject(String directory) throws IOException {
        System.out.println("Scanning project for JavaScript files in directory: " + directory);

        files = new ArrayList<>();
        checkBoxes = new ArrayList<>();

        try {
            // Gather all JS and JSX files
            files = Files.walk(Paths.get(directory))
                    .filter(path -> path.toString().endsWith(".js") || path.toString().endsWith(".jsx"))
                    .toList();
        } catch (IOException e) {
            System.out.println("No JavaScript code found!");
            throw new RuntimeException(e);
        }

        // If no files found, show a dialog and exit
        if (files.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No JavaScript files found!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Show the popup window with checkboxes
        showFileSelectionPopup(directory);
    }

    private static void showFileSelectionPopup(String directory) {
        JFrame frame = new JFrame("Select Files to Scan");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(400, 500);
        frame.setLayout(new BorderLayout());

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Checkbox for each file
        for (Path file : files) {
            JCheckBox checkBox = new JCheckBox(file.getFileName().toString(), true);
            checkBoxes.add(checkBox);
            panel.add(checkBox);
        }

        // Scroll Pane for File List
        JScrollPane scrollPane = new JScrollPane(panel);
        frame.add(scrollPane, BorderLayout.CENTER);

        // Footer Panel for Buttons
        JPanel footerPanel = new JPanel();
        JButton selectAllButton = new JButton("Select All");
        JButton startScanButton = new JButton("Start Scan");

        // Select All Button Action
        selectAllButton.addActionListener(e -> {
            boolean allSelected = checkBoxes.stream().allMatch(JCheckBox::isSelected);
            for (JCheckBox checkBox : checkBoxes) {
                checkBox.setSelected(!allSelected);
            }
        });

        // Start Scan Button Action
        startScanButton.addActionListener(e -> {
            List<String> selectedFiles = new ArrayList<>();
            for (int i = 0; i < checkBoxes.size(); i++) {
                if (checkBoxes.get(i).isSelected()) {
                    selectedFiles.add(files.get(i).toString());
                }
            }
            frame.dispose(); // Close the popup
            startScanning(selectedFiles);
        });

        footerPanel.add(selectAllButton);
        footerPanel.add(startScanButton);
        frame.add(footerPanel, BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private static void startScanning(List<String> selectedFiles) {
        System.out.println("\nStarting scan on selected files...");
        for (String filePath : selectedFiles) {
            try {
                scanFile(filePath);
            } catch (IOException e) {
                System.err.println("Error scanning file: " + filePath);
            }
        }
    }

    public static void scanFile(String filePath) throws IOException {
        System.out.println("Scanning file: " + filePath);
        // Implement your scanning logic here...
    }

    public static void main(String[] args) {
        try {
            scanProject("path/to/your/project"); // Replace with your actual project path
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
