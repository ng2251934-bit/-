import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

/**
 * 测试 BouncyCastle APK 签名
 */
public class SignTest {
    public static void main(String[] args) throws Exception {
        // Load keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("app/security_guard.keystore"), "SecurityGuard2024!".toCharArray());
        PrivateKey key = (PrivateKey) ks.getKey("security_guard_key", "SecurityGuard2024!".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("security_guard_key");

        // Create a test APK
        File testApk = new File("build/test_unsigned.apk");
        File signedApk = new File("build/test_signed.apk");

        // Create a minimal test APK
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(testApk));
        zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
        zos.write("<manifest package='com.test'/>".getBytes());
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("classes.dex"));
        zos.write(new byte[]{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00}); // dex magic
        zos.closeEntry();
        zos.close();

        // Sign using BouncyCastle
        signApk(testApk, signedApk, key, cert);

        System.out.println("Test APK signed: " + signedApk.exists());
        System.out.println("Size: " + signedApk.length());
    }

    static void signApk(File unsigned, File signed, PrivateKey key, X509Certificate cert) throws Exception {
        Map<String, byte[]> digestMap = new LinkedHashMap<>();
        Map<String, byte[]> fileData = new LinkedHashMap<>();

        ZipFile zip = new ZipFile(unsigned);
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (!entry.isDirectory() && !entry.getName().startsWith("META-INF/")) {
                byte[] data = zip.getInputStream(entry).readAllBytes();
                fileData.put(entry.getName(), data);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                digestMap.put(entry.getName(), md.digest(data));
            }
        }
        zip.close();

        // MANIFEST.MF
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Created-By", "SecurityGuard");
        for (Map.Entry<String, byte[]> e : digestMap.entrySet()) {
            Attributes attr = new Attributes();
            attr.putValue("SHA-256-Digest", Base64.getEncoder().encodeToString(e.getValue()));
            manifest.getEntries().put(e.getKey(), attr);
        }
        ByteArrayOutputStream mfBytes = new ByteArrayOutputStream();
        manifest.write(mfBytes);
        byte[] manifestRaw = mfBytes.toByteArray();

        // CERT.SF
        StringBuilder sf = new StringBuilder();
        sf.append("Signature-Version: 1.0\r\n");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        sf.append("SHA-256-Digest-Manifest: ").append(Base64.getEncoder().encodeToString(md.digest(manifestRaw))).append("\r\n");
        sf.append("Created-By: SecurityGuard\r\n\r\n");
        for (Map.Entry<String, byte[]> e : digestMap.entrySet()) {
            sf.append("Name: ").append(e.getKey()).append("\r\n");
            MessageDigest md2 = MessageDigest.getInstance("SHA-256");
            String entryHeader = "Name: " + e.getKey() + "\r\n";
            String entryDigest = "SHA-256-Digest: " + Base64.getEncoder().encodeToString(e.getValue()) + "\r\n\r\n";
            sf.append("SHA-256-Digest: ").append(Base64.getEncoder().encodeToString(md2.digest((entryHeader + entryDigest).getBytes()))).append("\r\n\r\n");
        }
        byte[] sfBytes = sf.toString().getBytes();

        // PKCS7
        List<X509Certificate> certList = new ArrayList<>();
        certList.add(cert);
        JcaCertStore certStore = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        JcaDigestCalculatorProviderBuilder dpb = new JcaDigestCalculatorProviderBuilder();
        JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(dpb.build());
        gen.addSignerInfoGenerator(sigb.build(new JcaContentSignerBuilder("SHA256withRSA").build(key), cert));
        gen.addCertificates(certStore);

        CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(sfBytes), true);
        byte[] pkcs7 = signedData.getEncoded();

        // Write signed APK - use ZipOutputStream not JarOutputStream to avoid duplicate MANIFEST.MF
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(signed));
        for (Map.Entry<String, byte[]> e : fileData.entrySet()) {
            zos.putNextEntry(new ZipEntry(e.getKey()));
            zos.write(e.getValue());
            zos.closeEntry();
        }
        zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
        zos.write(manifestRaw);
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("META-INF/CERT.SF"));
        zos.write(sfBytes);
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
        zos.write(pkcs7);
        zos.closeEntry();
        zos.close();
    }
}