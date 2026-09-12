package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import org.apache.maven.plugin.logging.Log;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.regex.Pattern;

public class PomModifier {

    private static final Pattern PROPERTY_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");
    private static final Pattern VERSION_RANGE_PATTERN = Pattern.compile("^[\\[(].*[)\\]]$");

    private final Log log;

    public PomModifier(Log log) {
        this.log = log;
    }

    public void backup(File pomFile, File outputDir) throws IOException {
        outputDir.mkdirs();
        File backup = new File(outputDir, "pom.xml.bak");
        Files.copy(pomFile.toPath(), backup.toPath(), StandardCopyOption.REPLACE_EXISTING);
        log.info("POM backup created at: " + backup.getAbsolutePath());
    }

    public int apply(File pomFile, List<UpgradeRecommendation> recommendations) {
        List<UpgradeRecommendation> applicable = recommendations.stream()
                .filter(r -> r.getStrategy() == UpgradeRecommendation.Strategy.UPGRADE_PATCH ||
                             r.getStrategy() == UpgradeRecommendation.Strategy.UPGRADE_MINOR)
                .filter(r -> r.getTargetVersion() != null)
                .collect(java.util.stream.Collectors.toList());

        if (applicable.isEmpty()) {
            log.info("No automatic upgrades to apply.");
            return 0;
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document doc;
            try (FileInputStream fis = new FileInputStream(pomFile)) {
                doc = builder.parse(fis);
            }

            int applied = 0;
            for (UpgradeRecommendation rec : applicable) {
                if (applyUpgrade(doc, rec)) {
                    applied++;
                }
            }

            if (applied > 0) {
                writeDocument(doc, pomFile);
                log.info("Applied " + applied + " upgrades to " + pomFile.getAbsolutePath());
            }

            return applied;

        } catch (Exception e) {
            log.error("Failed to modify POM: " + e.getMessage(), e);
            return 0;
        }
    }

    private boolean applyUpgrade(Document doc, UpgradeRecommendation rec) {
        String groupId = rec.getDependency().getGroupId();
        String artifactId = rec.getDependency().getArtifactId();
        String targetVersion = rec.getTargetVersion();

        // Find matching <dependency> element
        NodeList dependencies = doc.getElementsByTagName("dependency");
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dep = (Element) dependencies.item(i);
            String depGroup = getChildText(dep, "groupId");
            String depArtifact = getChildText(dep, "artifactId");

            if (groupId.equals(depGroup) && artifactId.equals(depArtifact)) {
                Element versionEl = getChildElement(dep, "version");
                if (versionEl == null) continue;

                String currentVersion = versionEl.getTextContent().trim();

                // Handle property references
                java.util.regex.Matcher propMatcher = PROPERTY_PATTERN.matcher(currentVersion);
                if (propMatcher.matches()) {
                    String propName = propMatcher.group(1);
                    if (updateProperty(doc, propName, targetVersion)) {
                        log.info("Updated property '" + propName + "' to " + targetVersion +
                                " for " + groupId + ":" + artifactId);
                        return true;
                    }
                    return false;
                }

                // Handle version ranges
                if (VERSION_RANGE_PATTERN.matcher(currentVersion).matches()) {
                    log.warn("Version range '" + currentVersion + "' in " + groupId + ":" + artifactId +
                            " cannot be automatically modified. Manual update required.");
                    return false;
                }

                // Direct version update
                versionEl.setTextContent(targetVersion);
                log.info("Upgraded " + groupId + ":" + artifactId + " from " + currentVersion + " to " + targetVersion);
                return true;
            }
        }

        log.debug("Dependency " + groupId + ":" + artifactId + " not found in POM dependencies section");
        return false;
    }

    private boolean updateProperty(Document doc, String propertyName, String newValue) {
        NodeList propertiesNodes = doc.getElementsByTagName("properties");
        for (int i = 0; i < propertiesNodes.getLength(); i++) {
            Element props = (Element) propertiesNodes.item(i);
            NodeList children = props.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                Node child = children.item(j);
                if (child instanceof Element && child.getNodeName().equals(propertyName)) {
                    child.setTextContent(newValue);
                    return true;
                }
            }
        }
        return false;
    }

    private String getChildText(Element parent, String tagName) {
        Element child = getChildElement(parent, tagName);
        return child != null ? child.getTextContent().trim() : "";
    }

    private Element getChildElement(Element parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element && child.getNodeName().equals(tagName)) {
                return (Element) child;
            }
        }
        return null;
    }

    private void writeDocument(Document doc, File file) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        transformer.setOutputProperty(OutputKeys.DOCTYPE_PUBLIC, "");

        try (FileOutputStream fos = new FileOutputStream(file)) {
            transformer.transform(new DOMSource(doc), new StreamResult(fos));
        }
    }
}
